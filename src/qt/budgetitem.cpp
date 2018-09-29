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
    if(!data.url.startsWith("http://") || !data.url.startsWith("https://")){
        data.url = "http://" + data.url;
    }
    ui->lblBudgetUrl->setText(data.url);
    ui->lblBudgetHash->setText("Hash:");
    ui->txtBudgetHash->setText(data.hash);
    ui->lblBudgetAddress->setText("Payment Address:");
    ui->txtBudgetAddress->setText(data.address);

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
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, tr("Budget Vote"), tr("Do you want to vote YES with yours masternodes?"), QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes) {
        uint256 nHash(hash.toUtf8().constData());
        std::string output = budget.voteManyBudget(nHash, VOTE_YES);
        QMessageBox box;
        box.setText(tr("Result") + ": \n" + QString::fromStdString(output));
        box.exec();
    }
}

void BudgetItem::on_pushVoteNo_clicked()
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, tr("Budget Vote"), tr("Do you want to vote NO with yours masternodes?"), QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes) {
        uint256 nHash(hash.toUtf8().constData());
        std::string output = budget.voteManyBudget(nHash, VOTE_NO);
        QMessageBox box;
        box.setText(tr("Result") + ": \n" + QString::fromStdString(output));
        box.exec();
    }
}

void BudgetItem::on_pushVoteAbstain_clicked()
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, tr("Budget Vote"), tr("Do you want to vote ABSTAIN with yours masternodes?"), QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes) {
        uint256 nHash(hash.toUtf8().constData());
        std::string output = budget.voteManyBudget(nHash, VOTE_ABSTAIN);
        QMessageBox box;
        box.setText(tr("Result") + ": \n" + QString::fromStdString(output));
        box.exec();
    }
}

void BudgetItem::on_lblBudgetUrl_clicked()
{
    QDesktopServices::openUrl ( QUrl(  ui->lblBudgetUrl->text()) );
}
