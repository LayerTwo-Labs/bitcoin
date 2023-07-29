// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bip345page.h>
#include <qt/forms/ui_bip345page.h>

BIP345Page::BIP345Page(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::BIP345Page)
{
    ui->setupUi(this);
}

BIP345Page::~BIP345Page()
{
    delete ui;
}
