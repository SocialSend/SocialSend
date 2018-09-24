#include "budgetitem.h"
#include "ui_budgetitem.h"

BudgetItem::BudgetItem(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::BudgetItem)
{
    ui->setupUi(this);

}


void BudgetItem::setData(BudgetData data)
{
    ui->lblBudgetName->setText(data.name);
    ui->lblBudgetUrl->setText(data.url);
    ui->lblBudgetHash->setText("Hash: " + data.hash);
    ui->lblBudgetAddress->setText("Payment Address: " + data.address);

    ui->lblVoteYes->setText("YES: " +  QString::number(data.yeas));
    ui->lblVoteNo->setText("NO: " +  QString::number(data.nays));
    ui->lblVoteAbstain->setText("ABSTAIN: " +  QString::number(data.abstain));

    ui->lblBlockStart->setText("Block Start: " +  QString::number(data.blockStart));
    ui->lblPaymentCount->setText("Payment Count: " +  QString::number(data.paymentCount));

    ui->lblMonthlyPayment->setText("Monthly Payment: " +  QString::number(data.monthlyPayment));
    ui->lblRemainingPayment->setText("Remaining Payment: " +  QString::number(data.remaingPayment));


    hash = data.hash;
}

BudgetItem::~BudgetItem()
{
    delete ui;
}

void BudgetItem::on_pushVoteYes_clicked()
{
    QMessageBox box;
    box.setText("On debug console:\nmnbudgetvote many " + hash + " yes" );
    box.exec();
}

void BudgetItem::on_pushVoteNo_clicked()
{
    QMessageBox box;
    box.setText("On debug console:\nmnbudgetvote many " + hash + " no" );
    box.exec();
}

void BudgetItem::on_pushVoteAbstain_clicked()
{
    QMessageBox box;
    box.setText("On debug console:\nmnbudgetvote many " + hash + " abstain" );
    box.exec();
}
