#ifndef ANNWIDGET_H
#define ANNWIDGET_H

#include <QWidget>


class AnnData{

public:
    QPixmap image;
    QString title;
    QString info;
    QString imageURL;
    int height;
    QString link;
};


namespace Ui {
class annWidget;



}


class annWidget : public QWidget
{
    Q_OBJECT

public:
    explicit annWidget(QWidget *parent = 0);
    ~annWidget();
    void setData(AnnData a);
    QSize getSize();
    QSize sizeHint() const;

private slots:
    void on_linkButton_clicked();

private:
    Ui::annWidget *ui;
};

#endif // ANNWIDGET_H
