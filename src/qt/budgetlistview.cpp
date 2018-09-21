#include "budgetlistview.h"
#include "ui_budgetlistview.h"

BudgetListView::BudgetListView(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::BudgetListView)
{
    ui->setupUi(this);
}

BudgetListView::~BudgetListView()
{
    delete ui;
}
