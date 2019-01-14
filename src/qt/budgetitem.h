#ifndef BUDGETITEM_H
#define BUDGETITEM_H

#include <QWidget>
#include <QMessageBox>
#include <QDesktopServices>
#include <QUrl>
#include "masternode-budget.h"
namespace Ui {
class BudgetItem;
class BudgetData;
}

class BudgetData{
public:
    QString name;
    QString url;
    QString hash;
    QString address;
    long blockStart;
    long paymentCount;
    long remaingPayment;
    long monthlyPayment;
    long yeas, nays, abstain;
    BudgetData(){}
};

class BudgetItem : public QWidget
{
    Q_OBJECT

public:
    explicit BudgetItem(QWidget *parent = 0);
    ~BudgetItem();
    void setData(BudgetData data);

private slots:
    void on_pushVoteYes_clicked();

    void on_pushVoteNo_clicked();

    void on_pushVoteAbstain_clicked();

    void on_lblBudgetUrl_clicked();

private:
    Ui::BudgetItem *ui;
    QString hash;
};

#endif // BUDGETITEM_H
