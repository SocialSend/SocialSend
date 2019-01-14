#include "budgetlistview.h"
#include "ui_budgetlistview.h"


#define VERTICAL_PADDING 10
#define HORIZONTAL_PADDING 10

BudgetListView::BudgetListView(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::BudgetListView)
{
    ui->setupUi(this);
    ui->titleLabel->setText(tr("Active Budget List"));
    ui->buttonReload->setText(tr("Reload"));
    list = new QVBoxLayout();
    list->setAlignment(Qt::AlignTop);
    ui->scrollBudgets->setLayout(list);
    loadBudgets();
    timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(timerTimeOut()));
    timer->start(1000);
}

void BudgetListView::timerTimeOut(){
    if(budget.hasChanges){
        budget.hasChanges = false;
        loadBudgets();
    }
}

void BudgetListView::loadBudgets(){

    QLayoutItem *child;
    while ((child = list->takeAt(0)) != 0) {
        delete child->widget();
        delete child;
    }

    std::vector<CBudgetProposal*> props = budget.GetAllProposals();
    int count = props.size();
    BOOST_FOREACH (CBudgetProposal* pbudgetProposal, props) {

        CTxDestination address1;
        ExtractDestination(pbudgetProposal->GetPayee(), address1);
        CBitcoinAddress address2(address1);

        BudgetData data;
        data.name = QString::fromStdString(pbudgetProposal->GetName());
        data.url = QString::fromStdString(pbudgetProposal->GetURL());
        data.hash = QString::fromStdString(pbudgetProposal->GetHash().ToString());
        data.address = QString::fromStdString( address2.ToString());
        data.blockStart = pbudgetProposal->GetBlockStart();
        data.paymentCount = pbudgetProposal->GetTotalPaymentCount();
        data.remaingPayment = pbudgetProposal->GetRemainingPaymentCount();
        data.monthlyPayment = (double)pbudgetProposal->GetAmount() /  100000000.0;
        data.yeas = pbudgetProposal->GetYeas();
        data.nays = pbudgetProposal->GetNays();
        data.abstain = pbudgetProposal->GetAbstains();

        BudgetItem *bi = new BudgetItem();

        bi->setData(data);
        list->addWidget(bi);
        count--;
        if(count > 0){
            QFrame *line = new QFrame;
            line->setFrameShape(QFrame::HLine);
            line->setFixedHeight(2);
            line->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            line->setStyleSheet(QString("background-color: #000000;"));
            list->addWidget(line);
        }
    }
    ui->textEdit->setText("Loaded " + QString::number(props.size()) + " budgets.");
}


BudgetListView::~BudgetListView()
{
    disconnect(timer, SIGNAL(timeout()), this, SLOT(timerTimeOut()));
    delete ui;
}

void BudgetListView::on_buttonReload_clicked()
{
    loadBudgets();
}
