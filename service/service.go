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
	"encoding/json"
	"fmt"
	common3 "github.com/ontio/ontology/common"
	common4 "github.com/ontio/ontology/smartcontract/service/native/cross_chain/common"
	"github.com/ontio/ontology/smartcontract/service/native/cross_chain/cross_chain_manager"
	"github.com/ontio/ontology/smartcontract/service/native/cross_chain/header_sync"
	common5 "github.com/polynetwork/ont-relayer/common"
	"github.com/polynetwork/ont-relayer/rest/http/restful"
	utils2 "github.com/polynetwork/ont-relayer/rest/utils"
	common2 "github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"os"
	"strconv"
	"strings"
	"time"

	sdk "github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology/smartcontract/service/native/utils"
	"github.com/polynetwork/ont-relayer/config"
	"github.com/polynetwork/ont-relayer/db"
	"github.com/polynetwork/ont-relayer/log"
	asdk "github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly-go-sdk/client"
	"github.com/polynetwork/poly/consensus/vbft/config"
	autils "github.com/polynetwork/poly/native/service/utils"
)

type SyncService struct {
	aliaAccount    *asdk.Account
	aliaSdk        *asdk.PolySdk
	aliaSyncHeight uint32
	sideAccount    *sdk.Account
	sideSdk        *sdk.OntologySdk
	sideSyncHeight uint32
	db             *db.BoltDB
	config         *config.Config
}

func NewSyncService(aliaAccount *asdk.Account, sideAccount *sdk.Account, aliaSdk *asdk.PolySdk, sideSdk *sdk.OntologySdk) *SyncService {
	if !checkIfExist(config.DefConfig.DBPath) {
		os.Mkdir(config.DefConfig.DBPath, os.ModePerm)
	}
	boltDB, err := db.NewBoltDB(config.DefConfig.DBPath)
	if err != nil {
		log.Errorf("db.NewWaitingDB error:%s", err)
		os.Exit(1)
	}
	syncSvr := &SyncService{
		aliaAccount: aliaAccount,
		aliaSdk:     aliaSdk,
		sideAccount: sideAccount,
		sideSdk:     sideSdk,
		db:          boltDB,
		config:      config.DefConfig,
	}
	return syncSvr
}

func (this *SyncService) Run() {
	go this.SideToAlliance()
	go this.AllianceToSide()
	go this.ProcessToAllianceCheckAndRetry()
}

func (this *SyncService) AllianceToSide() {
	currentSideChainSyncHeight, err := this.GetCurrentSideChainSyncHeight(this.aliaSdk.ChainId)
	if err != nil {
		log.Errorf("[AllianceToSide] this.GetCurrentSideChainSyncHeight error:", err)
		os.Exit(1)
	}
	this.sideSyncHeight = currentSideChainSyncHeight
	if config.DefConfig.AlliToSideForceSyncHeight > 0 {
		this.sideSyncHeight = uint32(config.DefConfig.AlliToSideForceSyncHeight)
	}

	for {
		currentAliaChainHeight, err := this.aliaSdk.GetCurrentBlockHeight()
		if err != nil {
			log.Errorf("[AllianceToSide] this.mainSdk.GetCurrentBlockHeight error:", err)
		}
		err = this.allianceToSide(this.sideSyncHeight, currentAliaChainHeight)
		if err != nil {
			log.Errorf("[AllianceToSide] this.allianceToSide error:", err)
		}
		time.Sleep(time.Duration(this.config.ScanInterval) * time.Second)
	}
}

func (this *SyncService) SideToAlliance() {
	currentAliaChainSyncHeight, err := this.GetCurrentAliaChainSyncHeight(this.GetSideChainID())
	if err != nil {
		log.Errorf("[SideToAlliance] this.GetCurrentAliaChainSyncHeight error:", err)
		os.Exit(1)
	}
	this.aliaSyncHeight = currentAliaChainSyncHeight
	if config.DefConfig.SideToAlliForceSyncHeight > 0 {
		this.aliaSyncHeight = uint32(config.DefConfig.SideToAlliForceSyncHeight)
	}
	for {
		currentSideChainHeight, err := this.sideSdk.GetCurrentBlockHeight()
		if err != nil {
			log.Errorf("[SideToAlliance] this.sideSdk.GetCurrentBlockHeight error:", err)
		}
		err = this.sideToAlliance(this.aliaSyncHeight, currentSideChainHeight)
		if err != nil {
			log.Errorf("[SideToAlliance] this.sideToAlliance error:", err)
		}

		time.Sleep(time.Duration(this.config.ScanInterval) * time.Second)
	}
}

func (this *SyncService) ProcessToAllianceCheckAndRetry() {
	for {
		err := this.checkDoneTx()
		if err != nil {
			log.Errorf("[ProcessToAllianceCheckAndRetry] this.checkDoneTx error:%s", err)
		}
		err = this.retryTx()
		if err != nil {
			log.Errorf("[ProcessToAllianceCheckAndRetry] this.retryTx error:%s", err)
		}
		time.Sleep(time.Duration(this.config.ScanInterval) * time.Second)
	}
}

func (this *SyncService) allianceToSide(m, n uint32) error {
	for i := m; i < n; i++ {
		log.Infof("[allianceToSide] start parse block %d", i)
		//sync key header
		blockHeader, err := this.aliaSdk.GetHeaderByHeight(i)
		if err != nil {
			return fmt.Errorf("[allianceToSide] this.aliaSdk.GetBlockByHeight error: %s", err)
		}
		blkInfo := &vconfig.VbftBlockInfo{}
		if err := json.Unmarshal(blockHeader.ConsensusPayload, blkInfo); err != nil {
			return fmt.Errorf("[allianceToSide] unmarshal blockInfo error: %s", err)
		}
		if blkInfo.NewChainConfig != nil {
			err = this.syncHeaderToSide(i)
			if err != nil {
				return fmt.Errorf("[allianceToSide] this.syncHeaderToSide error:%s", err)
			}
		}

		//sync cross chain info
		events, err := this.aliaSdk.GetSmartContractEventByBlock(i)
		if err != nil {
			return fmt.Errorf("[allianceToSide] this.aliaSdk.GetSmartContractEventByBlock error:%s", err)
		}
		for _, event := range events {
			for _, notify := range event.Notify {
				states, ok := notify.States.([]interface{})
				if !ok {
					continue
				}
				if notify.ContractAddress != autils.CrossChainManagerContractAddress.ToHexString() {
					continue
				}
				name := states[0].(string)
				if name == "makeProof" {
					if uint64(states[2].(float64)) == this.GetSideChainID() {
						key := states[5].(string)
						proof, err := this.aliaSdk.ClientMgr.GetCrossStatesProof(i, key)
						if err != nil {
							if strings.Contains(err.Error(), "http post request:") {
								return fmt.Errorf("[allianceToSide] GetCrossStatesProof error:%s", err)
							} else {
								log.Errorf("[allianceToSide] GetCrossStatesProof error:%s", err)
								continue
							}
						}
						auditpath, _ := hex.DecodeString(proof.AuditPath)
						value, _, _, _ := ParseAuditpath(auditpath)
						param := &common.ToMerkleValue{}
						if err := param.Deserialization(common2.NewZeroCopySource(value)); err != nil {
							log.Errorf("[allianceToSide] failed to deserialize MakeTxParam (value: %x, err: %v)", value, err)
							continue
						}

						var isTarget bool
						contractSet, ok := this.config.TargetContracts[strconv.FormatUint(param.MakeTxParam.ToChainID, 10)]
						if ok {
							toContract, err := common3.AddressParseFromBytes(param.MakeTxParam.ToContractAddress)
							if err != nil {
								log.Errorf("[allianceToSide] failed to get contract address from bytes: %v", err)
								continue
							}
							toContractStr := toContract.ToHexString()
							for _, v := range contractSet {
								if toContractStr == v {
									isTarget = true
									break
								}
							}
						}
						if !isTarget {
							continue
						}

						chainIDBytes := autils.GetUint64Bytes(this.aliaSdk.ChainId)
						heightBytes := autils.GetUint32Bytes(i + 1)
						var rawHeader []byte
						v, err := this.sideSdk.GetStorage(utils.HeaderSyncContractAddress.ToHexString(),
							common5.ConcatKey([]byte(header_sync.HEADER_INDEX), chainIDBytes, heightBytes))
						if len(v) == 0 {
							blockHeader, err := this.aliaSdk.GetHeaderByHeight(i + 1)
							if err != nil {
								log.Errorf("[allianceToSide] this.mainSdk.GetHeaderByHeight error:%s", err)
							}
							rawHeader = blockHeader.ToArray()
						}

						toContractAddr, err := common2.AddressParseFromBytes(param.MakeTxParam.ToContractAddress)
						if err != nil {
							log.Errorf("[allianceToSide] AddressParseFromBytes error: %v", err)
							continue
						}
						args := &utils2.TxArgs{}
						if err = args.Deserialization(common3.NewZeroCopySource(param.MakeTxParam.Args)); err != nil {
							return fmt.Errorf("[syncProofToAlia] failed to deserialize tx args: %v", err)
						}
						toAddr, err := common3.AddressParseFromBytes(args.ToAddr)
						if err != nil {
							log.Errorf("[allianceToSide] AddressParseFromBytes error: %v", err)
							continue
						}
						toAsset, err := common3.AddressParseFromBytes(args.ToAssetHash)
						if err != nil {
							log.Errorf("[allianceToSide] AddressParseFromBytes toAddr error: %v", err)
							continue
						}
						timeStart := time.Now()
					RETRY:
						if err := restful.FlamCli.SendOntInfo(
							param.MakeTxParam.ToChainID,
							args.Amt.Uint64(),
							toContractAddr.ToHexString(),
							cross_chain_manager.PROCESS_CROSS_CHAIN_TX,
							toAddr.ToBase58(),
							toAsset.ToHexString(),
							hex.EncodeToString(param.MakeTxParam.TxHash),
							[]string{
								strconv.FormatUint(this.aliaSdk.ChainId, 10),
								strconv.FormatUint(uint64(i+1), 10),
								proof.AuditPath,
								hex.EncodeToString(rawHeader),
							}); err != nil {
							if time.Now().Sub(timeStart) > this.config.RetryTimeout*time.Hour {
								log.Errorf("[allianceToSide] retry timeout and failed to send ( poly_hash: %s ) to flamingo: %v",
									event.TxHash, err)
								continue
							}
							log.Debugf("[allianceToSide] failed to send ( poly_hash: %s ) to flamingo and retry now: %s",
								event.TxHash, strings.Split(err.Error(), ",")[0])
							time.Sleep(time.Second * this.config.RetryDuration)
							goto RETRY
						}
						log.Infof("[allianceToSide] send ont info to flamingo ( poly_tx: %s )", event.TxHash)
					}
				}
			}
		}
		this.sideSyncHeight++
		if err := this.db.PutPolyHeight(i); err != nil {
			log.Errorf("failed to put poly height: %v", err)
		}
	}
	return nil
}

func (this *SyncService) sideToAlliance(m, n uint32) error {
	for i := m; i < n; i++ {
		log.Infof("[sideToAlliance] start parse block %d", i)
		//sync key header
		block, err := this.sideSdk.GetBlockByHeight(i)
		if err != nil {
			return fmt.Errorf("[sideToAlliance] this.sideSdk.GetBlockByHeight error: %s", err)
		}
		blkInfo := &vconfig.VbftBlockInfo{}
		if err := json.Unmarshal(block.Header.ConsensusPayload, blkInfo); err != nil {
			return fmt.Errorf("[sideToAlliance] unmarshal blockInfo error: %s", err)
		}
		if blkInfo.NewChainConfig != nil {
			err = this.syncHeaderToAlia(i)
			if err != nil {
				return fmt.Errorf("[sideToAlliance] this.syncHeaderToMain error:%s", err)
			}
		}

		//sync cross chain info
		events, err := this.sideSdk.GetSmartContractEventByBlock(i)
		if err != nil {
			return fmt.Errorf("[sideToAlliance] this.sideSdk.GetSmartContractEventByBlock error:%s", err)
		}
		confirmedTxArr := make([]string, 0)
		for _, event := range events {
			tx, err := this.sideSdk.GetTransaction(event.TxHash)
			if err != nil {
				return fmt.Errorf("[sideToAlliance] GetTransaction error:%s", err)
			}
			for _, notify := range event.Notify {
				states, ok := notify.States.([]interface{})
				if !ok {
					continue
				}
				if notify.ContractAddress != utils.CrossChainContractAddress.ToHexString() {
					continue
				}
				name := states[0].(string)
				if name == "verifyToOntProof" {
					confirmedTxArr = append(confirmedTxArr, states[2].(string))
				} else if name == "makeFromOntProof" {
					key := states[4].(string)

					k, err := hex.DecodeString(key)
					if err != nil {
						log.Errorf("[sideToAlliance] hex.DecodeString error: %s", err)
						continue
					}
					proof, err := this.sideSdk.GetCrossStatesProof(i, k)
					if err != nil {
						log.Errorf("[sideToAlliance] this.sideSdk.GetCrossStatesProof error: %s", err)
						continue
					}
					auditPath, err := hex.DecodeString(proof.AuditPath)
					if err != nil {
						log.Errorf("[sideToAlliance] hex.DecodeString error: %s", err)
						continue
					}
					value, _, _, _ := ParseAuditpath(auditPath)
					param := &common4.MakeTxParam{}
					if err := param.Deserialization(common3.NewZeroCopySource(value)); err != nil {
						log.Errorf("[sideToAlliance] failed to deserialize MakeTxParam (value: %x, err: %v)", value, err)
						continue
					}
					var isTarget bool
					contractSet, ok := this.config.TargetContracts[strconv.FormatUint(this.GetSideChainID(), 10)]
					if ok {
						fromContract, err := common3.AddressParseFromBytes(param.FromContractAddress)
						if err != nil {
							log.Errorf("[sideToAlliance] failed to get contract address from bytes: %v", err)
							continue
						}
						fromContractStr := fromContract.ToHexString()
						for _, v := range contractSet {
							if fromContractStr == v {
								isTarget = true
								break
							}
						}
					}
					if !isTarget {
						continue
					}

					txHash, err := this.syncProofToAlia(event.TxHash, key, tx, proof, i, param)
					if err != nil {
						_, ok := err.(client.PostErr)
						if ok {
							return fmt.Errorf("[sideToAlliance] this.syncProofToAlia error:%s", err)
						} else {
							log.Errorf("[sideToAlliance] this.syncProofToAlia error:%s", err)
						}
					}
					log.Infof("[sideToAlliance] syncProofToAlia ( poly_tx: %s, ont_tx: %s )",
						txHash.ToHexString(), event.TxHash)
				}
			}
		}
		this.aliaSyncHeight++
		if err := this.db.PutOntHeight(i); err != nil {
			log.Errorf("failed to put ont height: %v", err)
		}
		if len(confirmedTxArr) > 0 {
			if err := restful.FlamCli.SendConfirmedTxArr(confirmedTxArr); err != nil {
				log.Errorf("failed to send confirmed tx array: %v", err)
				//TODO: RETRY
			}
		}
	}
	return nil
}
