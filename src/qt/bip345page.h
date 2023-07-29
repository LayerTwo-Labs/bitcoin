// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BIP345PAGE_H
#define BIP345PAGE_H

#include <QWidget>

namespace Ui {
class BIP345Page;
}

class BIP345Page : public QWidget
{
    Q_OBJECT

public:
    explicit BIP345Page(QWidget *parent = nullptr);
    ~BIP345Page();

private:
    Ui::BIP345Page *ui;
};

#endif // BIP345PAGE_H
