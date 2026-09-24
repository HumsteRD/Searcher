#pragma once

#include "Page.h"

// «Справка»: короткие ответы на вопросы, которые возникают на деле.
class HelpPage : public Page {
    Q_OBJECT
public:
    explicit HelpPage(MainWindow* window);
};
