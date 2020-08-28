/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
 */
package service

import (
	"encoding/hex"
	"fmt"
	common2 "github.com/ontio/ontology/common"
	"github.com/ontio/ontology/core/types"
	common5 "github.com/ontio/ontology/http/base/common"
	common6 "github.com/ontio/ontology/smartcontract/service/native/cross_chain/common"
	"github.com/polynetwork/ont-relayer/rest/http/restful"
	utils2 "github.com/polynetwork/ont-relayer/rest/utils"
	"os"
	"strings"
	"time"

	"github.com/ontio/ontology/smartcontract/service/native/cross_chain/header_sync"
	"github.com/ontio/ontology/smartcontract/service/native/utils"
	"github.com/polynetwork/ont-relayer/common"
	"github.com/polynetwork/ont-relayer/db"
	"github.com/polynetwork/ont-relayer/log"
	acommon "github.com/polynetwork/poly/common"
	hscommon "github.com/polynetwork/poly/native/service/header_sync/common"
	autils "github.com/polynetwork/poly/native/service/utils"
)

var codeVersion = byte(0)

func (this *SyncService) GetSideChainID() uint64 {
	return this.config.SideChainID
}

func (this *SyncService) GetGasPrice() uint64 {
	return this.config.GasPrice
}

func (this *SyncService) GetGasLimit() uint64 {
	return this.config.GasLimit
}

func (this *SyncService) GetCurrentSideChainSyncHeight(aliaChainID uint64) (uint32, error) {
	contractAddress := utils.HeaderSyncContractAddress
	aliaChainIDBytes := common.GetUint64Bytes(aliaChainID)
	key := common.ConcatKey([]byte(header_sync.CURRENT_HEIGHT), aliaChainIDBytes)
	value, err := this.sideSdk.ClientMgr.GetStorage(contractAddress.ToHexString(), key)
	if err != nil {
		return 0, fmt.Errorf("getStorage error: %s", err)
	}
	height, err := utils.GetBytesUint32(value)
	if err != nil {
		return 0, fmt.Errorf("GetBytesUint32, get height error: %s", err)
	}
	if dbh := this.db.GetPolyHeight(); dbh > height {
		height = dbh
	}

	return height, nil
}

func (this *SyncService) GetCurrentAliaChainSyncHeight(sideChainID uint64) (uint32, error) {
	contractAddress := autils.HeaderSyncContractAddress
	sideChainIDBytes := common.GetUint64Bytes(sideChainID)

	key := common.ConcatKey([]byte(hscommon.CURRENT_MSG_HEIGHT), sideChainIDBytes)
	value, err := this.aliaSdk.ClientMgr.GetStorage(contractAddress.ToHexString(), key)
	if err != nil {
		return 0, fmt.Errorf("getStorage error: %s", err)
	}
	height := autils.GetBytesUint32(value)

	if height == 0 {
		key = common.ConcatKey([]byte(hscommon.CURRENT_HEADER_HEIGHT), sideChainIDBytes)
		value, err := this.aliaSdk.ClientMgr.GetStorage(contractAddress.ToHexString(), key)
		if err != nil {
			return 0, fmt.Errorf("getStorage error: %s", err)
		}
		height = autils.GetBytesUint32(value)
	}
	dbh := this.db.GetOntHeight()
	if dbh > height {
		height = dbh
	}

	return height, nil
}

func (this *SyncService) syncHeaderToAlia(height uint32) error {
	chainIDBytes := common.GetUint64Bytes(this.GetSideChainID())
	heightBytes := common.GetUint32Bytes(height)
	v, err := this.aliaSdk.GetStorage(autils.HeaderSyncContractAddress.ToHexString(),
		common.ConcatKey([]byte(hscommon.HEADER_INDEX), chainIDBytes, heightBytes))
	if len(v) != 0 {
		return nil
	}
	block, err := this.sideSdk.GetBlockByHeight(height)
	if err != nil {
		return fmt.Errorf("[syncHeaderToAlia] this.sideSdk.GetBlockByHeight error: %s", err)
	}
	txHash, err := this.aliaSdk.Native.Hs.SyncBlockHeader(this.GetSideChainID(), this.aliaAccount.Address, [][]byte{block.Header.ToArray()},
		this.aliaAccount)
	if err != nil {
		return fmt.Errorf("[syncHeaderToAlia] invokeNativeContract error: %s", err)
	}
	log.Infof("[syncHeaderToAlia] syncHeaderToAlia txHash is :", txHash.ToHexString())
	this.waitForAliaBlock()
	return nil
}

func (this *SyncService) syncCrossChainMsgToAlia(height uint32) error {
	chainIDBytes := common.GetUint64Bytes(this.GetSideChainID())
	heightBytes := common.GetUint32Bytes(height)
	v, err := this.aliaSdk.GetStorage(autils.HeaderSyncContractAddress.ToHexString(),
		common.ConcatKey([]byte(hscommon.CROSS_CHAIN_MSG), chainIDBytes, heightBytes))
	if len(v) != 0 {
		return nil
	}
	crossChainMsg, err := this.sideSdk.GetCrossChainMsg(height)
	if err != nil {
		return fmt.Errorf("[syncCrossChainMsgToAlia] this.sideSdk.GetCrossChainMsg error: %s", err)
	}
	params, err := hex.DecodeString(crossChainMsg)
	if err != nil {
		return fmt.Errorf("[syncCrossChainMsgToAlia] hex.DecodeString error: %s", err)
	}
	txHash, err := this.aliaSdk.Native.Hs.SyncCrossChainMsg(this.GetSideChainID(), this.aliaAccount.Address,
		[][]byte{params}, this.aliaAccount)
	if err != nil {
		return fmt.Errorf("[syncCrossChainMsgToAlia] invokeNativeContract error: %s", err)
	}
	log.Infof("[syncCrossChainMsgToAlia] syncHeaderToAlia txHash is :", txHash.ToHexString())
	this.waitForAliaBlock()
	return nil
}

func (this *SyncService) syncProofToAlia(ontTx, key string, tx *types.Transaction, proof *common5.CrossStatesProof, height uint32, param *common6.MakeTxParam) (acommon.Uint256, error) {
	chainIDBytes := common.GetUint64Bytes(this.GetSideChainID())
	heightBytes := common.GetUint32Bytes(height)
	params := []byte{}
	v, err := this.aliaSdk.GetStorage(autils.HeaderSyncContractAddress.ToHexString(),
		common.ConcatKey([]byte(hscommon.CROSS_CHAIN_MSG), chainIDBytes, heightBytes))
	if len(v) == 0 {
		crossChainMsg, err := this.sideSdk.GetCrossChainMsg(height)
		if err != nil {
			return acommon.UINT256_EMPTY, fmt.Errorf("[syncProofToAlia] this.sideSdk.GetCrossChainMsg error: %s", err)
		}
		params, err = hex.DecodeString(crossChainMsg)
		if err != nil {
			return acommon.UINT256_EMPTY, fmt.Errorf("[syncProofToAlia] hex.DecodeString error: %s", err)
		}
	}

	auditPath, err := hex.DecodeString(proof.AuditPath)
	if err != nil {
		return acommon.UINT256_EMPTY, fmt.Errorf("[syncProofToAlia] hex.DecodeString error: %s", err)
	}
	args := &utils2.TxArgs{}
	if err = args.Deserialization(common2.NewZeroCopySource(param.Args)); err != nil {
		return acommon.UINT256_EMPTY, fmt.Errorf("[syncProofToAlia] failed to deserialize tx args: %v", err)
	}
	fromContract, err := common2.AddressParseFromBytes(param.FromContractAddress)
	if err != nil {
		return acommon.UINT256_EMPTY, fmt.Errorf("[syncProofToAlia] failed to AddressParseFromBytes: %v", err)
	}
	retry := &db.Retry{
		Height:              height,
		Key:                 key,
		OntTx:               ontTx,
		ToChainId:           param.ToChainID,
		Sender:              tx.SignedAddr[0],
		Args:                param.Args,
		FromContractAddress: fromContract,
	}
	sink := acommon.NewZeroCopySink(nil)
	retry.Serialization(sink)

	txHash, terr := this.aliaSdk.Native.Ccm.ImportOuterTransfer(this.GetSideChainID(), nil, height, auditPath,
		this.aliaAccount.Address[:], params, this.aliaAccount)
	if terr != nil {
		if strings.Contains(terr.Error(), "chooseUtxos, current utxo is not enough") {
			log.Infof("[syncProofToAlia] invokeNativeContract error: %s", err)
			err = this.db.PutRetry(sink.Bytes())
			if err != nil {
				return acommon.UINT256_EMPTY, fmt.Errorf("[syncProofToAlia] this.db.PutRetry error: %s", err)
			}
			log.Infof("[syncProofToAlia] put tx into retry db, height %d, key %s", height, key)
			return acommon.UINT256_EMPTY, nil
		} else {
			timeStart := time.Now()
		RETRY1:
			if err := restful.FlamCli.SendTxPair(
				this.GetSideChainID(),
				param.ToChainID,
				tx.SignedAddr[0].ToBase58(),
				hex.EncodeToString(args.ToAddr),
				acommon.UINT256_EMPTY.ToHexString(),
				ontTx,
				fromContract.ToHexString(),
				args.Amt.Uint64(),
				-1); err != nil {
				if time.Now().Sub(timeStart) > this.config.RetryTimeout*time.Hour {
					log.Errorf("[syncProofToAlia] failed to send tx pair (ont_tx: %s, status: FAILED, error: %v)",
						ontTx, err)
					return acommon.UINT256_EMPTY, terr
				}
				log.Debugf("[syncProofToAlia] failed to send tx pair (ont_tx: %s, status: FAILED, error: %v)",
					ontTx, strings.Split(err.Error(), ",")[0])
				time.Sleep(time.Second * this.config.RetryDuration)
				goto RETRY1
			}
			log.Infof("[syncProofToAlia] success to send tx pair (ont_tx: %s, status: FAILED, error: %v)",
				ontTx, err)
			return acommon.UINT256_EMPTY, terr
		}
	}
	if err = this.db.PutCheck(txHash.ToHexString(), sink.Bytes()); err != nil {
		return acommon.UINT256_EMPTY, fmt.Errorf("[syncProofToAlia] this.db.PutCheck error: %s", err)
	}
	timeStart := time.Now()
RETRY2:
	if err = restful.FlamCli.SendTxPair(
		this.GetSideChainID(),
		param.ToChainID,
		tx.SignedAddr[0].ToBase58(),
		hex.EncodeToString(args.ToAddr),
		txHash.ToHexString(),
		ontTx,
		fromContract.ToHexString(),
		args.Amt.Uint64(),
		1); err != nil {
		if time.Now().Sub(timeStart) > this.config.RetryTimeout*time.Hour {
			log.Errorf("[syncProofToAlia] failed to send tx pair (ont_tx: %s, status: pending, error: %v)",
				ontTx, err)
			return txHash, nil
		}
		log.Debugf("[syncProofToAlia] failed to send tx pair (ont_tx: %s, status: pending, error: %v)",
			ontTx, strings.Split(err.Error(), ",")[0])
		time.Sleep(time.Second * this.config.RetryDuration)
		goto RETRY2
	}
	log.Infof("[syncProofToAlia] success to send tx pair (poly_tx: %s, ont_tx: %s, status: PENDING)",
		txHash.ToHexString(), ontTx, err)

	return txHash, nil
}

func (this *SyncService) retrySyncProofToAlia(v []byte) error {
	retry := new(db.Retry)
	err := retry.Deserialization(acommon.NewZeroCopySource(v))
	if err != nil {
		return fmt.Errorf("[retrySyncProofToAlia] retry.Deserialization error: %s", err)
	}
	k, err := hex.DecodeString(retry.Key)
	if err != nil {
		return fmt.Errorf("[retrySyncProofToAlia] hex.DecodeString error: %s", err)
	}
	proof, err := this.sideSdk.GetCrossStatesProof(retry.Height, k)
	if err != nil {
		return fmt.Errorf("[retrySyncProofToAlia] this.sideSdk.GetCrossStatesProof error: %s", err)
	}
	auditPath, err := hex.DecodeString(proof.AuditPath)
	if err != nil {
		return fmt.Errorf("[retrySyncProofToAlia] hex.DecodeString error: %s", err)
	}
	chainIDBytes := common.GetUint64Bytes(this.GetSideChainID())
	heightBytes := common.GetUint32Bytes(retry.Height)
	params := []byte{}
	s, err := this.aliaSdk.GetStorage(autils.HeaderSyncContractAddress.ToHexString(),
		common.ConcatKey([]byte(hscommon.CROSS_CHAIN_MSG), chainIDBytes, heightBytes))
	if len(s) == 0 {
		crossChainMsg, err := this.sideSdk.GetCrossChainMsg(retry.Height)
		if err != nil {
			return fmt.Errorf("[retrySyncProofToAlia] this.sideSdk.GetCrossChainMsg error: %s", err)
		}
		params, err = hex.DecodeString(crossChainMsg)
		if err != nil {
			return fmt.Errorf("[retrySyncProofToAlia] hex.DecodeString error: %s", err)
		}
	}
	args := &utils2.TxArgs{}
	if err = args.Deserialization(common2.NewZeroCopySource(retry.Args)); err != nil {
		return fmt.Errorf("[syncProofToAlia] failed to deserialize tx args: %v", err)
	}

	txHash, terr := this.aliaSdk.Native.Ccm.ImportOuterTransfer(this.GetSideChainID(),
		nil, retry.Height, auditPath, this.aliaAccount.Address[:], params, this.aliaAccount)
	if terr != nil {
		if strings.Contains(terr.Error(), "chooseUtxos, current utxo is not enough") {
			log.Infof("[retrySyncProofToAlia] invokeNativeContract error: %s", err)
			return nil
		} else {
			if err := this.db.DeleteRetry(v); err != nil {
				return fmt.Errorf("[retrySyncProofToAlia] this.db.DeleteRetry error: %s", err)
			}
			timeStart := time.Now()
		RETRY1:
			err := restful.FlamCli.SendTxPair(
				this.GetSideChainID(),
				retry.ToChainId,
				retry.Sender.ToBase58(),
				hex.EncodeToString(args.ToAddr),
				acommon.UINT256_EMPTY.ToHexString(),
				retry.OntTx,
				retry.FromContractAddress.ToHexString(),
				args.Amt.Uint64(),
				-1)
			if err != nil {
				if time.Now().Sub(timeStart) > this.config.RetryTimeout*time.Hour {
					log.Errorf("[retrySyncProofToAlia] failed to send tx pair (ont_tx: %s, status: FAILED, error: %v)",
						retry.OntTx, err)
					return fmt.Errorf("[retrySyncProofToAlia] invokeNativeContract error: %s", terr)
				}
				log.Debugf("[retrySyncProofToAlia] failed to send tx pair (ont_tx: %s, status: FAILED, error: %v)",
					retry.OntTx, strings.Split(err.Error(), ",")[0])
				time.Sleep(time.Second * this.config.RetryDuration)
				goto RETRY1
			}
			log.Infof("[retrySyncProofToAlia] success to send tx pair (ont_tx: %s, status: FAILED, error: %v)",
				retry.OntTx, err)
			return fmt.Errorf("[retrySyncProofToAlia] invokeNativeContract error: %s", terr)
		}
	}
	err = this.db.PutCheck(txHash.ToHexString(), v)
	if err != nil {
		return fmt.Errorf("[retrySyncProofToAlia] this.db.PutCheck error: %s", err)
	}
	err = this.db.DeleteRetry(v)
	if err != nil {
		return fmt.Errorf("[retrySyncProofToAlia] this.db.DeleteRetry error: %s", err)
	}

	log.Infof("[retrySyncProofToAlia] syncProofToAlia (ont_tx: %s, poly_tx: %s, status: PENDING)",
		retry.OntTx, txHash.ToHexString())
	timeStart := time.Now()
RETRY2:
	if err := restful.FlamCli.SendTxPair(
		this.GetSideChainID(),
		retry.ToChainId,
		retry.Sender.ToBase58(),
		hex.EncodeToString(args.ToAddr),
		txHash.ToHexString(),
		retry.OntTx,
		retry.FromContractAddress.ToHexString(),
		args.Amt.Uint64(),
		1); err != nil {
		if time.Now().Sub(timeStart) > this.config.RetryTimeout*time.Hour {
			log.Errorf("[retrySyncProofToAlia] failed to send tx pair (ont_tx: %s, status: PENDING, error: %v)",
				retry.OntTx, err)
			return nil
		}
		log.Debugf("[retrySyncProofToAlia] failed to send tx pair (ont_tx: %s, status: PENDING, error: %v)",
			retry.OntTx, strings.Split(err.Error(), ",")[0])
		time.Sleep(time.Second * this.config.RetryDuration)
		goto RETRY2
	}
	log.Infof("[retrySyncProofToAlia] success to send tx pair (ont_tx: %s, poly_tx: %s, status: PENDING)",
		retry.OntTx, txHash.ToHexString())
	return nil
}

func (this *SyncService) syncHeaderToSide(height uint32) error {
	chainIDBytes := common.GetUint64Bytes(this.aliaSdk.ChainId)
	heightBytes := common.GetUint32Bytes(height)
	v, err := this.sideSdk.GetStorage(utils.HeaderSyncContractAddress.ToHexString(),
		common.ConcatKey([]byte(header_sync.HEADER_INDEX), chainIDBytes, heightBytes))
	if len(v) != 0 {
		return nil
	}
	contractAddress := utils.HeaderSyncContractAddress
	method := header_sync.SYNC_BLOCK_HEADER
	blockHeader, err := this.aliaSdk.GetHeaderByHeight(height)
	if err != nil {
		log.Errorf("[syncHeaderToSide] this.mainSdk.GetHeaderByHeight error:%s", err)
	}
	param := &header_sync.SyncBlockHeaderParam{
		Headers: [][]byte{blockHeader.ToArray()},
	}
	txHash, err := this.sideSdk.Native.InvokeNativeContract(this.GetGasPrice(), this.GetGasLimit(), this.sideAccount,
		this.sideAccount, codeVersion, contractAddress, method, []interface{}{param})
	if err != nil {
		return fmt.Errorf("[syncHeaderToSide] invokeNativeContract error: %s", err)
	}
	log.Infof("[syncHeaderToSide] syncHeaderToSide txHash is :", txHash.ToHexString())
	this.waitForSideBlock()
	return nil
}

func (this *SyncService) checkDoneTx() error {
	checkMap, err := this.db.GetAllCheck()
	if err != nil {
		return fmt.Errorf("[checkDoneTx] this.db.GetAllCheck error: %s", err)
	}
	for k, v := range checkMap {
		event, err := this.aliaSdk.GetSmartContractEvent(k)
		if err != nil {
			return fmt.Errorf("[checkDoneTx] this.aliaSdk.GetSmartContractEvent error: %s", err)
		}
		if event == nil {
			log.Infof("[checkDoneTx] can not find event of hash %s", k)
			continue
		}
		polyStatus := 0
		if event.State != 1 {
			log.Infof("[checkDoneTx] state of tx %s is not success", k)
			err := this.db.PutRetry(v)
			if err != nil {
				return fmt.Errorf("[checkDoneTx] this.db.PutRetry error:%s", err)
			}
			polyStatus = -1
		}
		retry := &db.Retry{}
		if err := retry.Deserialization(acommon.NewZeroCopySource(v)); err != nil {
			return fmt.Errorf("[checkDoneTx] failed to Deserialization: %v", err)
		}
		args := &utils2.TxArgs{}
		if err = args.Deserialization(common2.NewZeroCopySource(retry.Args)); err != nil {
			return fmt.Errorf("[checkDoneTx] failed to deserialize tx args: %v", err)
		}
		err = this.db.DeleteCheck(k)
		if err != nil {
			log.Errorf("[checkDoneTx] this.db.DeleteCheck error:%s", err)
		}
		timeStart := time.Now()
	RETRY:
		if err := restful.FlamCli.UpdateTxPair(
			this.GetSideChainID(),
			retry.ToChainId,
			retry.Sender.ToBase58(),
			hex.EncodeToString(args.ToAddr),
			k,
			retry.OntTx,
			retry.FromContractAddress.ToHexString(),
			args.Amt.Uint64(),
			polyStatus); err != nil {
			if time.Now().Sub(timeStart) > this.config.RetryTimeout*time.Hour {
				log.Errorf("[checkDoneTx] - failed to update tx pair ( poly_txhash: %s, ont_txhash: %s, status: %d, error: %v)",
					k, retry.OntTx, polyStatus, err)
				continue
			}
			log.Debugf("[checkDoneTx] failed to update tx pair ( poly_txhash: %s, ont_txhash: %s, status: %d, error: %s)",
				k, retry.OntTx, polyStatus, strings.Split(err.Error(), ",")[0])
			time.Sleep(time.Second * this.config.RetryDuration)
			goto RETRY
		}
		log.Infof("[checkDoneTx] success to send tx pair ( poly_txhash: %s, ont_txhash: %s, status: %d )", k, retry.OntTx, polyStatus)
	}

	return nil
}

func (this *SyncService) retryTx() error {
	retryList, err := this.db.GetAllRetry()
	if err != nil {
		return fmt.Errorf("[retryTx] this.db.GetAllRetry error: %s", err)
	}
	for _, v := range retryList {
		err = this.retrySyncProofToAlia(v)
		if err != nil {
			log.Errorf("[retryTx] this.retrySyncProofToAlia error:%s", err)
		}
		time.Sleep(time.Duration(this.config.RetryInterval) * time.Second)
	}

	return nil
}

func (this *SyncService) waitForAliaBlock() {
	_, err := this.aliaSdk.WaitForGenerateBlock(90*time.Second, 3)
	if err != nil {
		log.Errorf("waitForAliaBlock error:%s", err)
	}
}

func (this *SyncService) waitForSideBlock() {
	_, err := this.sideSdk.WaitForGenerateBlock(90*time.Second, 3)
	if err != nil {
		log.Errorf("waitForSideBlock error:%s", err)
	}
}

func checkIfExist(dir string) bool {
	_, err := os.Stat(dir)
	if err != nil && !os.IsExist(err) {
		return false
	}
	return true
}

func ParseAuditpath(path []byte) ([]byte, []byte, [][32]byte, error) {
	source := acommon.NewZeroCopySource(path)
	/*
		l, eof := source.NextUint64()
		if eof {
			return nil, nil, nil, nil
		}
	*/
	value, eof := source.NextVarBytes()
	if eof {
		return nil, nil, nil, nil
	}
	size := int((source.Size() - source.Pos()) / acommon.UINT256_SIZE)
	pos := make([]byte, 0)
	hashs := make([][32]byte, 0)
	for i := 0; i < size; i++ {
		f, eof := source.NextByte()
		if eof {
			return nil, nil, nil, nil
		}
		pos = append(pos, f)

		v, eof := source.NextHash()
		if eof {
			return nil, nil, nil, nil
		}
		var onehash [32]byte
		copy(onehash[:], (v.ToArray())[0:32])
		hashs = append(hashs, onehash)
	}

	return value, pos, hashs, nil
}
