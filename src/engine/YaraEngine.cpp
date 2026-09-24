#include "YaraEngine.h"
#include "SignatureStore.h"
#include "../core/Logger.h"

#include <yara.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>

namespace fs = std::filesystem;

namespace {

struct CompileContext {
    int         errors = 0;
    int         warnings = 0;
    std::string firstError;
};

void OnCompileMessage(int level, const char* file, int line, const YR_RULE*,
                      const char* message, void* user)
{
    auto* ctx = static_cast<CompileContext*>(user);
    if (level == YARA_ERROR_LEVEL_ERROR) {
        if (ctx->errors++ == 0) {
            ctx->firstError = std::string(file ? file : "rules") + ":" +
                              std::to_string(line) + ": " + (message ? message : "");
        }
    } else {
        ++ctx->warnings;
    }
}

struct ScanContext {
    std::vector<YaraEngine::Hit>* hits;
};

int OnScanMessage(YR_SCAN_CONTEXT*, int message, void* data, void* user) {
    if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;

    auto* ctx  = static_cast<ScanContext*>(user);
    auto* rule = static_cast<YR_RULE*>(data);

    YaraEngine::Hit hit;
    hit.rule = rule->identifier ? rule->identifier : "";

    const YR_META* meta = nullptr;
    yr_rule_metas_foreach(rule, meta) {
        const std::string key = meta->identifier ? meta->identifier : "";
        if (meta->type == META_TYPE_INTEGER) {
            if (key == "score")   hit.score   = static_cast<int>(meta->integer);
            if (key == "quality") hit.quality = static_cast<int>(meta->integer);
        } else if (meta->type == META_TYPE_STRING && meta->string) {
            if (key == "description" && hit.description.empty()) hit.description = meta->string;
            if (key == "author" && hit.author.empty())           hit.author = meta->string;
            // В части правил оценка записана строкой.
            if (key == "score" && hit.score == 0) hit.score = std::atoi(meta->string);
        }
    }
    if (hit.score == 0) hit.score = 70;   // значение YARA-Forge по умолчанию

    ctx->hits->push_back(std::move(hit));
    // Больше полутора десятков совпадений к вердикту ничего не добавляют.
    return ctx->hits->size() >= 16 ? CALLBACK_ABORT : CALLBACK_CONTINUE;
}

std::string ReadWhole(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string Fingerprint(const std::vector<fs::path>& files) {
    std::string s;
    std::error_code ec;
    for (const auto& f : files) {
        s += f.string() + "|" + std::to_string(fs::file_size(f, ec)) + "|" +
             std::to_string(fs::last_write_time(f, ec).time_since_epoch().count()) + ";";
    }
    return s;
}

} // namespace

YaraEngine& YaraEngine::Get() {
    static YaraEngine engine;
    return engine;
}

YaraEngine::YaraEngine() {
    initialized_ = (yr_initialize() == ERROR_SUCCESS);
    if (!initialized_) Logger::Instance().Error("[YARA] initialization failed");
}

YaraEngine::~YaraEngine() {
    std::unique_lock lock(lock_);
    if (rules_) yr_rules_destroy(rules_);
    rules_ = nullptr;
    if (initialized_) yr_finalize();
}

bool YaraEngine::Ready() const {
    std::shared_lock lock(lock_);
    return rules_ != nullptr;
}

int YaraEngine::RuleCount() const {
    std::shared_lock lock(lock_);
    return ruleCount_;
}

bool YaraEngine::Prepare(bool includeExtended, std::string* error) {
    if (!initialized_) {
        if (error) *error = "YARA engine failed to initialize";
        return false;
    }

    std::vector<fs::path> files;
    const fs::path core = SignatureStore::RulesFile("core");
    if (!core.empty()) files.push_back(core);
    if (includeExtended) {
        // Расширенный пакет YARA-Forge включает core целиком, поэтому
        // при выбранном расширенном наборе core отдельно не грузим.
        const fs::path ext = SignatureStore::RulesFile("extended");
        if (!ext.empty()) files = { ext };
    }
    if (files.empty()) {
        if (error) *error = "no YARA rule files found";
        Logger::Instance().Warn("[YARA] no rule files found in the signatures folders");
        return false;
    }

    const std::string fp = Fingerprint(files);
    {
        std::shared_lock lock(lock_);
        if (rules_ && fp == fingerprint_) return true;
    }

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS) {
        if (error) *error = "cannot create YARA compiler";
        return false;
    }

    CompileContext ctx;
    yr_compiler_set_callback(compiler, OnCompileMessage, &ctx);

    for (const auto& f : files) {
        const std::string text = ReadWhole(f);
        if (text.empty()) continue;
        yr_compiler_add_string(compiler, text.c_str(), nullptr);
        if (ctx.errors) break;   // после ошибки компилятор больше ничего не примет
    }

    YR_RULES* compiled = nullptr;
    if (ctx.errors == 0) yr_compiler_get_rules(compiler, &compiled);
    yr_compiler_destroy(compiler);

    if (!compiled) {
        if (error) *error = "YARA rules failed to compile: " + ctx.firstError;
        Logger::Instance().Error("[YARA] compile failed: " + ctx.firstError);
        return false;
    }

    int count = 0;
    YR_RULE* rule = nullptr;
    yr_rules_foreach(compiled, rule) { ++count; }

    {
        std::unique_lock lock(lock_);
        if (rules_) yr_rules_destroy(rules_);
        rules_       = compiled;
        ruleCount_   = count;
        fingerprint_ = fp;
    }
    Logger::Instance().Info("[YARA] " + std::to_string(count) + " rules ready (" +
                            (includeExtended ? "extended" : "core") + " set)");
    return true;
}

std::vector<YaraEngine::Hit> YaraEngine::Scan(const uint8_t* data, size_t size,
                                              int timeoutSec) const
{
    std::vector<Hit> hits;
    if (!data || size == 0) return hits;

    std::shared_lock lock(lock_);
    if (!rules_) return hits;

    ScanContext ctx{ &hits };
    const int rc = yr_rules_scan_mem(rules_, data, size, SCAN_FLAGS_FAST_MODE,
                                     OnScanMessage, &ctx, timeoutSec);
    if (rc != ERROR_SUCCESS && rc != ERROR_SCAN_TIMEOUT) {
        Logger::Instance().Debug("[YARA] scan error " + std::to_string(rc));
    }
    return hits;
}

std::vector<YaraEngine::Hit> YaraEngine::ScanHandle(void* fileHandle, int timeoutSec) const {
    std::vector<Hit> hits;
    if (!fileHandle) return hits;

    std::shared_lock lock(lock_);
    if (!rules_) return hits;

    ScanContext ctx{ &hits };
    const int rc = yr_rules_scan_fd(rules_, static_cast<YR_FILE_DESCRIPTOR>(fileHandle),
                                    SCAN_FLAGS_FAST_MODE, OnScanMessage, &ctx, timeoutSec);
    if (rc != ERROR_SUCCESS && rc != ERROR_SCAN_TIMEOUT) {
        Logger::Instance().Debug("[YARA] scan error " + std::to_string(rc));
    }
    return hits;
}
