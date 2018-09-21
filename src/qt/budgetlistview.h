#ifndef BUDGETLISTVIEW_H
#define BUDGETLISTVIEW_H

#include <QWidget>

namespace Ui {
class BudgetListView;
}

class BudgetListView : public QWidget
{
    Q_OBJECT

public:
    explicit BudgetListView(QWidget *parent = 0);
    ~BudgetListView();

private:
    Ui::BudgetListView *ui;
};

#endif // BUDGETLISTVIEW_H
