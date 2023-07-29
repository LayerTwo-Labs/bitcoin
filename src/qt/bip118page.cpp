// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/bip118page.h>
#include <qt/forms/ui_bip118page.h>

BIP118Page::BIP118Page(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::BIP118Page)
{
    ui->setupUi(this);
}

BIP118Page::~BIP118Page()
{
    delete ui;
}
