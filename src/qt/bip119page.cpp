// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bip119page.h>
#include <qt/forms/ui_bip119page.h>

BIP119Page::BIP119Page(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::BIP119Page)
{
    ui->setupUi(this);
}

BIP119Page::~BIP119Page()
{
    delete ui;
}
