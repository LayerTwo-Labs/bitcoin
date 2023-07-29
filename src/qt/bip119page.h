// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BIP119PAGE_H
#define BIP119PAGE_H

#include <QWidget>

namespace Ui {
class BIP119Page;
}

class BIP119Page : public QWidget
{
    Q_OBJECT

public:
    explicit BIP119Page(QWidget *parent = nullptr);
    ~BIP119Page();

private:
    Ui::BIP119Page *ui;
};

#endif // BIP119PAGE_H
