#ifndef ANNOUNCEMENTVIEW_H
#define ANNOUNCEMENTVIEW_H

#include <QWidget>
#include "annwidget.h"
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrl>
#include <QList>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonValue>
#include <QJsonObject>
#include <QListWidget>
#include <QListWidgetItem>



namespace Ui {
class AnnouncementView;



}

class AnnouncementView : public QWidget
{
    Q_OBJECT

public:
    explicit AnnouncementView(QWidget *parent = 0);
    ~AnnouncementView();

private:
    int lastUpdate=0;
    Ui::AnnouncementView *ui;
    QList<AnnData> annList;
    int annNumber = 0;
private slots:
    void replyFinished (QNetworkReply *reply);
    void replyFinishedImage (QNetworkReply *reply);

//    void on_annList_currentItemChanged(QListWidgetItem *current, QListWidgetItem *previous);
    void on_pushButton_clicked();
};

#endif // ANNOUNCEMENTVIEW_H
