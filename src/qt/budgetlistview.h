#ifndef BUDGETLISTVIEW_H
#define BUDGETLISTVIEW_H

#include <QObject>
#include <QAbstractItemDelegate>
#include <QModelIndex>
#include <QSize>
#include <QSpinBox>
#include <QPainter>
#include <QWidget>
#include <QtGui>
#include <QtCore>
#include <QVBoxLayout>
#include "masternode-budget.h"
#include "budgetitem.h"

namespace Ui {
class BudgetListView;
class BudgetData;
}


class BudgetListView : public QWidget
{
    Q_OBJECT

public:
    explicit BudgetListView(QWidget *parent = 0);
    ~BudgetListView();
    void loadBudgets();

private:
    Ui::BudgetListView *ui;
    QVBoxLayout *list;
};



#endif // BUDGETLISTVIEW_H
