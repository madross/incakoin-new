#ifndef INCAKOINADDRESSVALIDATOR_H
#define INCAKOINADDRESSVALIDATOR_H

#include <QRegExpValidator>

/** Base48 entry widget validator.
   Corrects near-miss characters and refuses characters that are no part of base48.
 */
class IncaKoinAddressValidator : public QValidator
{
    Q_OBJECT
public:
    explicit IncaKoinAddressValidator(QObject *parent = 0);

    State validate(QString &input, int &pos) const;

    static const int MaxAddressLength = 35;
signals:

public slots:

};

#endif // INCALOINADDRESSVALIDATOR_H
