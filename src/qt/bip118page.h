// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BIP118PAGE_H
#define BIP118PAGE_H

#include <QWidget>

namespace Ui {
class BIP118Page;
}

class BIP118Page : public QWidget
{
    Q_OBJECT

public:
    explicit BIP118Page(QWidget *parent = nullptr);
    ~BIP118Page();

private:
    Ui::BIP118Page *ui;
};

#endif // BIP118PAGE_H
