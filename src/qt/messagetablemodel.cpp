// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "messagetablemodel.h"

#include "addresstablemodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "messagerecord.h"
#include "walletmodel.h"

#include "core_io.h"
#include "main.h"
#include "sync.h"
#include "uint256.h"
#include "util.h"
#include "wallet/wallet.h"

#include <QColor>
#include <QDateTime>
#include <QDebug>
#include <QIcon>
#include <QList>

#include <boost/foreach.hpp>

// Amount column is right-aligned it contains numbers
static int column_alignments[] = {
        Qt::AlignLeft|Qt::AlignVCenter, /* status */
        Qt::AlignLeft|Qt::AlignVCenter, /* encrypted */
        Qt::AlignLeft|Qt::AlignVCenter, /* date */
        Qt::AlignLeft|Qt::AlignVCenter, /* from */
        Qt::AlignLeft|Qt::AlignVCenter, /* subj */
        Qt::AlignLeft|Qt::AlignVCenter /* to */
    };

// Comparison operator for sort/binary search of model tx list
struct TxLessThan
{
    bool operator()(const MessageRecord &a, const MessageRecord &b) const
    {
        return a.hash < b.hash;
    }
    bool operator()(const MessageRecord &a, const uint256 &b) const
    {
        return a.hash < b;
    }
    bool operator()(const uint256 &a, const MessageRecord &b) const
    {
        return a < b.hash;
    }
};

// Private implementation
class MessageTablePriv
{
public:
    MessageTablePriv(CWallet *wallet, MessageTableModel *parent, WalletModel *model) :
        wallet(wallet),
        parent(parent),
        model(model)
    {
    }

    CWallet *wallet;
    MessageTableModel *parent;
    WalletModel *model;

    /* Local cache of wallet.
     * As it is in the same order as the CWallet, by definition
     * this is sorted by sha256.
     */
    QList<MessageRecord> cachedWallet;

    /* Query entire wallet anew from core.
     */
    void refreshWallet()
    {
        cachedWallet.clear();
        qDebug() << "MessageTablePriv::refreshWallet.insize() = " << cachedWallet.size();
        {
            LOCK2(cs_main, wallet->cs_wallet);
            for(std::map<uint256, CWalletTx>::iterator it = wallet->mapWallet.begin(); it != wallet->mapWallet.end(); ++it)
            {
                if(MessageRecord::showMessage(it->second))
                {
                    QList<MessageRecord> lList = MessageRecord::decomposeMessage(wallet, it->second, model);
                    for (QList<MessageRecord>::iterator lItem = lList.begin(); lItem != lList.end(); lItem++)
                    {
                        if ((*lItem).haveFromPubKey)
                        {
                            parent->addPubKey((*lItem).from, (*lItem).fromPubKey);
                        }
                    }
                    cachedWallet.append(lList);
                }
            }
        }

        qDebug() << "MessageTablePriv::refreshWallet.outsize() = " << cachedWallet.size();
    }

    /* Update our model of the wallet incrementally, to synchronize our model of the wallet
       with that of the core.

       Call with Message that was added, removed or changed.
     */
    void updateWallet(const uint256 &hash, int status, bool showMessage)
    {
        qDebug() << "MessageTablePriv::updateWallet: " + QString::fromStdString(hash.ToString()) + " " + QString::number(status);

        // Find bounds of this Message in model
        QList<MessageRecord>::iterator lower = qLowerBound(
            cachedWallet.begin(), cachedWallet.end(), hash, TxLessThan());
        QList<MessageRecord>::iterator upper = qUpperBound(
            cachedWallet.begin(), cachedWallet.end(), hash, TxLessThan());
        int lowerIndex = (lower - cachedWallet.begin());
        int upperIndex = (upper - cachedWallet.begin());
        bool inModel = (lower != upper);

        if(status == CT_UPDATED)
        {
            if(showMessage && !inModel)
                status = CT_NEW; /* Not in model, but want to show, treat as new */
            if(!showMessage && inModel)
                status = CT_DELETED; /* In model, but want to hide, treat as deleted */
        }

        qDebug() << "    inModel=" + QString::number(inModel) +
                    " Index=" + QString::number(lowerIndex) + "-" + QString::number(upperIndex) +
                    " showMessage=" + QString::number(showMessage) + " derivedStatus=" + QString::number(status);

        switch(status)
        {
        case CT_NEW:
            if(inModel)
            {
                qWarning() << "MessageTablePriv::updateWallet: Warning: Got CT_NEW, but Message is already in model";
                break;
            }
            if(showMessage)
            {
                LOCK2(cs_main, wallet->cs_wallet);
                // Find Message in wallet
                std::map<uint256, CWalletTx>::iterator mi = wallet->mapWallet.find(hash);
                if(mi == wallet->mapWallet.end())
                {
                    qWarning() << "MessageTablePriv::updateWallet: Warning: Got CT_NEW, but Message is not in wallet";
                    break;
                }
                // Added -- insert at the right position
                QList<MessageRecord> toInsert =
                        MessageRecord::decomposeMessage(wallet, mi->second, model);
                if(!toInsert.isEmpty()) /* only if something to insert */
                {
                    parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex+toInsert.size()-1);
                    int insert_idx = lowerIndex;
                    Q_FOREACH(const MessageRecord &rec, toInsert)
                    {
                        qDebug() << "\tupdate - tx = " << rec.hash.ToString().c_str();
                        cachedWallet.insert(insert_idx, rec);
                        if (rec.haveFromPubKey) parent->addPubKey(rec.from, rec.fromPubKey);
                        insert_idx += 1;
                    }
                    parent->endInsertRows();
                }
            }
            break;
        case CT_DELETED:
            if(!inModel)
            {
                qWarning() << "MessageTablePriv::updateWallet: Warning: Got CT_DELETED, but Message is not in model";
                break;
            }
            // Removed -- remove entire Message from table
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedWallet.erase(lower, upper);
            parent->endRemoveRows();
            break;
        case CT_UPDATED:
            // Miscellaneous updates -- nothing to do, status update will take care of this, and is only computed for
            // visible Messages.
            break;
        }
    }

    int size()
    {
        return cachedWallet.size();
    }

    MessageRecord *index(int idx)
    {
        if(idx >= 0 && idx < cachedWallet.size())
        {
            MessageRecord *rec = &cachedWallet[idx];

            // Get required locks upfront. This avoids the GUI from getting
            // stuck if the core is holding the locks for a longer time - for
            // example, during a wallet rescan.
            //
            // If a status update is needed (blocks came in since last check),
            //  update the status of this Message from the wallet. Otherwise,
            // simply re-use the cached status.
            TRY_LOCK(cs_main, lockMain);
            if(lockMain)
            {
                TRY_LOCK(wallet->cs_wallet, lockWallet);
                if(lockWallet && rec->statusUpdateNeeded())
                {
                    std::map<uint256, CWalletTx>::iterator mi = wallet->mapWallet.find(rec->hash);

                    if(mi != wallet->mapWallet.end())
                    {
                        rec->updateStatus(mi->second);
                    }
                }
            }
            return rec;
        }
        return 0;
    }

    QString describe(MessageRecord *rec, int unit)
    {
        {
            LOCK2(cs_main, wallet->cs_wallet);
            std::map<uint256, CWalletTx>::iterator mi = wallet->mapWallet.find(rec->hash);
            if(mi != wallet->mapWallet.end())
            {
                return QString("");
                //return MessageDesc::toHTML(wallet, mi->second, rec, unit);
            }
        }
        return QString();
    }

    QString getTxHex(MessageRecord *rec)
    {
        LOCK2(cs_main, wallet->cs_wallet);
        std::map<uint256, CWalletTx>::iterator mi = wallet->mapWallet.find(rec->hash);
        if(mi != wallet->mapWallet.end())
        {
            std::string strHex = EncodeHexTx(static_cast<CTransaction>(mi->second));
            return QString::fromStdString(strHex);
        }
        return QString();
    }
};

MessageTableModel::MessageTableModel(const PlatformStyle *platformStyle, CWallet* wallet, WalletModel *parent):
        QAbstractTableModel(parent),
        wallet(wallet),
        walletModel(parent),
        priv(new MessageTablePriv(wallet, this, parent)),
        fProcessingQueuedMessages(false),
        platformStyle(platformStyle)
{
    //         state        encrypted
    columns << QString() << QString() << tr("Date") << tr("From") << tr("Subj") << tr("To");
    priv->refreshWallet();

    subscribeToCoreSignals();
}

MessageTableModel::~MessageTableModel()
{
    unsubscribeFromCoreSignals();
    delete priv;
}

void MessageTableModel::addPubKey(const std::string& address, const CPubKey& pubKey)
{
    LOCK2(cs_main, wallet->cs_wallet);
    if (pubKeyCache.find(address) == pubKeyCache.end())
    {
        pubKeyCache.insert(std::make_pair(address, pubKey));
    }
}

bool MessageTableModel::getPubKey(const std::string& address, CPubKey& pubKey)
{
    LOCK2(cs_main, wallet->cs_wallet);
    std::map<std::string, CPubKey>::iterator lFound = pubKeyCache.find(address);
    if (lFound != pubKeyCache.end())
    {
        pubKey.Set(lFound->second.begin(), lFound->second.end());
        return true;
    }

    return false;
}

void MessageTableModel::updateMessage(const QString &hash, int status, bool showMessage)
{
    uint256 updated;
    updated.SetHex(hash.toStdString());

    priv->updateWallet(updated, status, showMessage);
}

int MessageTableModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int MessageTableModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QString MessageTableModel::formatTxStatus(const MessageRecord *wtx) const
{
    QString status;

    switch(wtx->status.status)
    {
    case MessageStatus::OpenUntilBlock:
        status = tr("Open for %n more block(s)","",wtx->status.open_for);
        break;
    case MessageStatus::OpenUntilDate:
        status = tr("Open until %1").arg(GUIUtil::dateTimeStr(wtx->status.open_for));
        break;
    case MessageStatus::Offline:
        status = tr("Offline");
        break;
    case MessageStatus::Unconfirmed:
        status = tr("Unconfirmed");
        break;
    case MessageStatus::Abandoned:
        status = tr("Abandoned");
        break;
    case MessageStatus::Confirming:
        status = tr("Confirming (%1 of %2 recommended confirmations)").arg(wtx->status.depth).arg(MessageRecord::RecommendedNumConfirmations);
        break;
    case MessageStatus::Confirmed:
        status = tr("Confirmed (%1 confirmations)").arg(wtx->status.depth);
        break;
    case MessageStatus::Conflicted:
        status = tr("Conflicted");
        break;
    case MessageStatus::Immature:
        status = tr("Immature (%1 confirmations, will be available after %2)").arg(wtx->status.depth).arg(wtx->status.depth + wtx->status.matures_in);
        break;
    case MessageStatus::MaturesWarning:
        status = tr("This block was not received by any other nodes and will probably not be accepted!");
        break;
    case MessageStatus::NotAccepted:
        status = tr("Generated but not accepted");
        break;
    }

    return status;
}

QString MessageTableModel::formatTxDate(const MessageRecord *wtx) const
{
    if(wtx->time)
    {
        return GUIUtil::dateTimeStr(wtx->time);
    }
    return QString();
}

/* Look up address in address book, if found return label (address)
   otherwise just return (address)
 */
QString MessageTableModel::lookupAddress(const std::string &address, bool tooltip) const
{
    QString label = walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(address));
    QString description;
    if(!label.isEmpty())
    {
        description += label;
    }
    if(label.isEmpty() || tooltip)
    {
        description += QString(" (") + QString::fromStdString(address) + QString(")");
    }
    return description;
}

QString MessageTableModel::formatTxType(const MessageRecord *wtx) const
{
    switch(wtx->type)
    {
    case MessageRecord::RecvFromAddress:
        return tr("Received from");
    case MessageRecord::SendToAddress:
        return tr("Send to");
    default:
        return QString();
    }
}

QVariant MessageTableModel::txAddressDecoration(const MessageRecord *wtx) const
{
    /*
        TODO: useful icons may be to indicate someone
    */
    return QVariant();
}

QString MessageTableModel::formatToAddress(const MessageRecord *wtx, bool tooltip) const
{
    switch(wtx->type)
    {
    case MessageRecord::SendToAddress:
        return lookupAddress(wtx->to, tooltip);
    case MessageRecord::RecvFromAddress:
        return lookupAddress(wtx->to, tooltip);
    default:
        return tr("(n/a)");
    }
}

QString MessageTableModel::formatFromAddress(const MessageRecord *wtx, bool tooltip) const
{
    switch(wtx->type)
    {
    case MessageRecord::RecvFromAddress:
        return lookupAddress(wtx->from, tooltip);
    case MessageRecord::SendToAddress:
        return lookupAddress(wtx->from, tooltip);
    default:
        return tr("(n/a)");
    }
}

QVariant MessageTableModel::addressColor(const MessageRecord *wtx) const
{
    // Show addresses without label in a less visible color
    switch(wtx->type)
    {
    case MessageRecord::RecvFromAddress:
        {
        QString label = walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(wtx->from));
        if(label.isEmpty())
            return COLOR_BAREADDRESS;
        } break;
    case MessageRecord::SendToAddress:
        {
        QString label = walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(wtx->to));
        if(label.isEmpty())
            return COLOR_BAREADDRESS;
        } break;
    default:
        break;
    }
    return QVariant();
}

QVariant MessageTableModel::txStatusDecoration(const MessageRecord *wtx) const
{
    switch(wtx->type)
    {
    case MessageRecord::RecvFromAddress:
        return QIcon(":/icons/tx_input");
    case MessageRecord::SendToAddress:
        return QIcon(":/icons/tx_output");
    default:
        return QIcon(":/icons/tx_inout");
    }
}

QVariant MessageTableModel::txEncryptedDecoration(const MessageRecord *wtx) const
{
    if(wtx->encrypted)
    {
        return QIcon(":/icons/key");
    }

    return QVariant();
}

QVariant MessageTableModel::txWatchonlyDecoration(const MessageRecord *wtx) const
{
    if (wtx->involvesWatchAddress)
        return QIcon(":/icons/eye");
    else
        return QVariant();
}

QString MessageTableModel::formatTooltip(const MessageRecord *rec) const
{
    QString tooltip = formatTxStatus(rec) + QString("\n") + formatTxType(rec);
    if(rec->type==MessageRecord::RecvFromAddress)
    {
        tooltip += QString(" ") + formatFromAddress(rec, true);
    }
    else if(rec->type==MessageRecord::SendToAddress)
    {
        tooltip += QString(" ") + formatToAddress(rec, true);
    }
    return tooltip;
}

QVariant MessageTableModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid())
        return QVariant();
    MessageRecord *rec = static_cast<MessageRecord*>(index.internalPointer());

    switch(role)
    {
    case RecordRole: return qVariantFromValue((void*)rec);
    case RawDecorationRole:
        switch(index.column())
        {
        case Status:
            return txStatusDecoration(rec);
        case Encrypted:
            return txEncryptedDecoration(rec);
        case FromAddress:
            return txAddressDecoration(rec);
        case ToAddress:
            return txAddressDecoration(rec);
        }
        break;
    case Qt::DecorationRole:
    {
        QIcon icon = qvariant_cast<QIcon>(index.data(RawDecorationRole));
        return platformStyle->TextColorIcon(icon);
    }
    case Qt::DisplayRole:
        switch(index.column())
        {
        case Subj:
            return rec->DecodeSubj();
        case Date:
            return formatTxDate(rec);
        case FromAddress:
            return formatFromAddress(rec, false);
        case ToAddress:
            return formatToAddress(rec, false);
        }
        break;
    case Qt::EditRole:
        // Edit role is used for sorting, so return the unformatted values
        switch(index.column())
        {
        case Status:
            return QString::fromStdString(rec->status.sortKey);
        case Date:
            return rec->time;
        case FromAddress:
            return formatFromAddress(rec, true);
        case ToAddress:
            return formatToAddress(rec, true);
        }
        break;
    case Qt::ToolTipRole:
        return formatTooltip(rec);
    case Qt::TextAlignmentRole:
        return column_alignments[index.column()];
    case Qt::ForegroundRole:
        // Use the "danger" color for abandoned Messages
        if(rec->status.status == MessageStatus::Abandoned)
        {
            return COLOR_TX_STATUS_DANGER;
        }
        // Non-confirmed (but not immature) as Messages are grey
        if(!rec->status.countsForBalance && rec->status.status != MessageStatus::Immature)
        {
            return COLOR_UNCONFIRMED;
        }
        if(index.column() == ToAddress) //?
        {
            return addressColor(rec);
        }
        break;
    case TypeRole:
        return rec->type;
    case DateRole:
        return QDateTime::fromTime_t(static_cast<uint>(rec->time));
    case LongDescriptionRole:
        return priv->describe(rec, walletModel->getOptionsModel()->getDisplayUnit());
    case FromAddressRole:
        return QString::fromStdString(rec->from); //walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(rec->from));
    case ToAddressRole:
        return QString::fromStdString(rec->to); // walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(rec->to));
    case SubjRole:
        return rec->DecodeSubj();
    case TxIDRole:
        return rec->getTxID();
    case TxHashRole:
        return QString::fromStdString(rec->hash.ToString());
    case TxHexRole:
        return priv->getTxHex(rec);
    case DecodedMessageRole:
        return rec->DecodeMessage();
    case TxPlainTextRole:
        {
            QString details;
            QDateTime date = QDateTime::fromTime_t(static_cast<uint>(rec->time));
            QString txFromLabel = walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(rec->from));
            QString txToLabel = walletModel->getAddressTableModel()->labelForAddress(QString::fromStdString(rec->to));

            details.append(date.toString("M/d/yy HH:mm"));
            details.append(" ");
            details.append(formatTxStatus(rec));
            details.append(". ");
            if(!formatTxType(rec).isEmpty()) {
                details.append(formatTxType(rec));
                details.append(" ");
            }
            if(!rec->from.empty()) {
                if(txFromLabel.isEmpty())
                    details.append(tr("(no label)") + " ");
                else {
                    details.append("(");
                    details.append(txFromLabel);
                    details.append(") ");
                }
                details.append(QString::fromStdString(rec->from));
                details.append(" ");
            }
            if(!rec->to.empty()) {
                if(txToLabel.isEmpty())
                    details.append(tr("(no label)") + " ");
                else {
                    details.append("(");
                    details.append(txToLabel);
                    details.append(") ");
                }
                details.append(QString::fromStdString(rec->to));
                details.append(" ");
            }

            details.append(rec->DecodeMessage());
            return details;
        }
    case ConfirmedRole:
        return rec->status.countsForBalance;
    case StatusRole:
        return rec->status.status;
    }
    return QVariant();
}

QVariant MessageTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Horizontal)
    {
        if(role == Qt::DisplayRole)
        {
            return columns[section];
        }
        else if (role == Qt::TextAlignmentRole)
        {
            return column_alignments[section];
        } else if (role == Qt::ToolTipRole)
        {
            switch(section)
            {
            case Status:
                return tr("Message status. Hover over this field to show number of confirmations.");
            case Date:
                return tr("Date and time that the Message was received.");
            case FromAddress:
                return tr("Sender address.");
            case ToAddress:
                return tr("Recipient address.");
            }
        }
    }
    return QVariant();
}

QModelIndex MessageTableModel::index(int row, int column, const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    MessageRecord *data = priv->index(row);
    if(data)
    {
        return createIndex(row, column, priv->index(row));
    }
    return QModelIndex();
}

// queue notifications to show a non freezing progress dialog e.g. for rescan
struct MessageNotification
{
public:
    MessageNotification() {}
    MessageNotification(uint256 hash, ChangeType status, bool showMessage):
        hash(hash), status(status), showMessage(showMessage) {}

    void invoke(QObject *ttm)
    {
        QString strHash = QString::fromStdString(hash.GetHex());
        qDebug() << "NotifyMessageChanged: " + strHash + " status= " + QString::number(status);
        QMetaObject::invokeMethod(ttm, "updateMessage", Qt::QueuedConnection,
                                  Q_ARG(QString, strHash),
                                  Q_ARG(int, status),
                                  Q_ARG(bool, showMessage));
    }
private:
    uint256 hash;
    ChangeType status;
    bool showMessage;
};

static bool fQueueNotifications = false;
static std::vector< MessageNotification > vQueueNotifications;

static void NotifyMessageChanged(QAbstractTableModel *ttm, CWallet *wallet, const uint256 &hash, ChangeType status)
{
    // Find Message in wallet
    std::map<uint256, CWalletTx>::iterator mi = wallet->mapWallet.find(hash);
    // Determine whether to show Message or not (determine this here so that no relocking is needed in GUI thread)
    bool inWallet = mi != wallet->mapWallet.end();
    bool showMessage = (inWallet && MessageRecord::showMessage(mi->second));

    MessageNotification notification(hash, status, showMessage);

    if (fQueueNotifications)
    {
        vQueueNotifications.push_back(notification);
        return;
    }
    notification.invoke(ttm);
}

static void ShowProgress(QAbstractTableModel *ttm, const std::string &title, int nProgress)
{
    if (nProgress == 0)
        fQueueNotifications = true;

    if (nProgress == 100)
    {
        fQueueNotifications = false;
        if (vQueueNotifications.size() > 10) // prevent balloon spam, show maximum 10 balloons
            QMetaObject::invokeMethod(ttm, "setProcessingQueuedMessages", Qt::QueuedConnection, Q_ARG(bool, true));
        for (unsigned int i = 0; i < vQueueNotifications.size(); ++i)
        {
            if (vQueueNotifications.size() - i <= 10)
                QMetaObject::invokeMethod(ttm, "setProcessingQueuedMessages", Qt::QueuedConnection, Q_ARG(bool, false));

            vQueueNotifications[i].invoke(ttm);
        }
        std::vector<MessageNotification >().swap(vQueueNotifications); // clear
    }
}

void MessageTableModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    // TODO: we need a message notification method
    wallet->NotifyTransactionChanged.connect(boost::bind(NotifyMessageChanged, this, boost::placeholders::_1, boost::placeholders::_2, boost::placeholders::_3));
    wallet->ShowProgress.connect(boost::bind(ShowProgress, this, boost::placeholders::_1, boost::placeholders::_2));
}

void MessageTableModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    // TODO: we need a message notification method
    wallet->NotifyTransactionChanged.disconnect(boost::bind(NotifyMessageChanged, this, boost::placeholders::_1, boost::placeholders::_2, boost::placeholders::_3));
    wallet->ShowProgress.disconnect(boost::bind(ShowProgress, this, boost::placeholders::_1, boost::placeholders::_2));
}
