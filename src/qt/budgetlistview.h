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
#include <QTimer>
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

private slots:
    void on_buttonReload_clicked();
    void timerTimeOut();

private:
    Ui::BudgetListView *ui;
    QVBoxLayout *list;
    QTimer *timer;
};



#endif // BUDGETLISTVIEW_H
