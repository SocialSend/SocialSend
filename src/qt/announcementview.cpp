#include "announcementview.h"
#include "ui_announcementview.h"
#include <QMessageBox>
#include <QModelIndex>

void AnnouncementView::replyFinished(QNetworkReply *reply)
{
    if(reply->error())
    {
        qDebug() << "ERROR!";
        qDebug() << reply->errorString();

    }
    else
    {

        QString json = reply->readAll();

        QJsonDocument jdoc = QJsonDocument::fromJson(json.toUtf8());
        if(jdoc.isNull()){
            reply->deleteLater();
            return;
        }

        QJsonObject response = jdoc.object();

        QString status = response["status"].toString();
        if(status.isEmpty() || (status != "ok") ){
            reply->deleteLater();
            return;
        }

        QJsonArray jsonANNs = response["data"].toArray();
        annList.clear();
        annNumber = 0;

        foreach(QJsonValue obj, jsonANNs){
            QJsonObject ann = obj.toObject();
            AnnData a;
            a.title = ann["title"].toString();
            a.info = ann["info"].toString();
            a.imageURL = ann["url"].toString();
            a.link =ann["link"].toString();
            //a.image = Null;
            annList << a;
            /*
            annWidget *ann_item = new annWidget(this);
            ann_item->setData(a);
            QListWidgetItem *item = new QListWidgetItem();
            item->setSizeHint(QSize(0, 75));
            ui->annList->addItem(item);
            ui->annList->setItemWidget(item, ann_item );*/
        }

        if(annList.isEmpty()){
            reply->deleteLater();
            return;
        }
        int time = response["time"].toInt();
        if(time > lastUpdate){

            lastUpdate = time;

            QLayoutItem *child;
            while ((child = ui->verticalLayout->takeAt(0)) != 0) {
                delete child->widget();
                delete child;
            }

            QNetworkAccessManager *manager = new QNetworkAccessManager(this);
            connect(manager, SIGNAL(finished(QNetworkReply*)), this, SLOT(replyFinishedImage(QNetworkReply*)));

            manager->get(QNetworkRequest(QUrl(annList[0].imageURL)));
        }else{
             ui->pushButton->setEnabled(true);
        }


    }
    reply->deleteLater();
}

void AnnouncementView::replyFinishedImage(QNetworkReply *reply)
{
    if(reply->error())
    {
        qDebug() << "ERROR!";
        qDebug() << reply->errorString();

    }
    else
    {


        QByteArray jpegData = reply->readAll();
        QPixmap pixmap;

        pixmap.loadFromData(jpegData);
        if (!pixmap.isNull())
        {
            annList[annNumber].image = pixmap;
            annWidget *ann_item = new annWidget(this);
            annList[annNumber].height = ann_item->getSize().height();
            ann_item->setData(annList[annNumber]);

            /*QListWidgetItem *item = new QListWidgetItem();

            int listWidth = ui->annList->width();

            //ann_item->setFixedSize(QSize(listWidth,200));
            //item->setSizeHint(ann_item->getSize());

            //item->setSizeHint(QSize(0, 75));
            ui->annList->addItem(item);
            ui->annList->setItemWidget(item, ann_item );
*/

            ui->verticalLayout->addWidget(ann_item);

            annNumber++;
            if(annNumber <= annList.size() -1){
                QNetworkAccessManager *manager = new QNetworkAccessManager(this);
                connect(manager, SIGNAL(finished(QNetworkReply*)), this, SLOT(replyFinishedImage(QNetworkReply*)));

                manager->get(QNetworkRequest(QUrl(annList[annNumber].imageURL)));
            }else{
                ui->pushButton->setEnabled(true);
            }
        }



    }
    reply->deleteLater();
}

AnnouncementView::AnnouncementView(QWidget *parent) :   QWidget(parent),
                                                        ui(new Ui::AnnouncementView)
{
    ui->setupUi(this);
    ui->verticalLayout_3->setAlignment(Qt::AlignTop);
    lastUpdate = 0;
    ui->mainTitleLable->setText(tr("Social Send Announcement"));
    ui->pushButton->setText(tr("Refresh"));
    //Load Announcement data
    QNetworkAccessManager *manager = new QNetworkAccessManager(this);
    connect(manager, SIGNAL(finished(QNetworkReply*)), this, SLOT(replyFinished(QNetworkReply*)));

    manager->get(QNetworkRequest(QUrl("http://socialsend.info/feed/annjson.php")));

    /* Load delegate
    ui->annList->setItemDelegate(anndelegate);
    model = new QStandardItemModel();
    ui->annList->setModel(model);//connect the model to view.
*/
}

AnnouncementView::~AnnouncementView()
{
    delete ui;
}


/*
void AnnouncementView::on_annList_currentItemChanged(QListWidgetItem *current, QListWidgetItem *previous)
{


    if(previous) previous->setSizeHint(QSize(0, 75));
    if(current){
        int index = ui->annList->row(current);

        annWidget dummyAnn;
        dummyAnn.setData(annList[index]);
        int listWidth = ui->annList->width();
        dummyAnn.setFixedSize(QSize(listWidth,500));
        QSize s = dummyAnn.getSize();
        if(s.height()<75)
            current->setSizeHint(QSize(listWidth,75));
        else
            current->setSizeHint(QSize(listWidth,s.height()));
    }
}
*/

void AnnouncementView::on_pushButton_clicked()
{
    annList.clear();
    annNumber=0;


    QNetworkAccessManager *manager = new QNetworkAccessManager(this);
    connect(manager, SIGNAL(finished(QNetworkReply*)), this, SLOT(replyFinished(QNetworkReply*)));

    manager->get(QNetworkRequest(QUrl("http://socialsend.info/feed/annjson.php")));
    ui->pushButton->setEnabled(false);
}
