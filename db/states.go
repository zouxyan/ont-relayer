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
package db

import (
	"fmt"
	common2 "github.com/ontio/ontology/common"
	"github.com/polynetwork/poly/common"
)

type Retry struct {
	Height              uint32
	Key                 string
	OntTx               string
	ToChainId           uint64
	Sender              common2.Address
	Args                []byte
	FromContractAddress common2.Address
}

func (this *Retry) Serialization(sink *common.ZeroCopySink) {
	sink.WriteUint32(this.Height)
	sink.WriteString(this.Key)
	sink.WriteString(this.OntTx)
	sink.WriteUint64(this.ToChainId)
	sink.WriteVarBytes(this.Sender[:])
	sink.WriteVarBytes(this.Args)
	sink.WriteVarBytes(this.FromContractAddress[:])
}

func (this *Retry) Deserialization(source *common.ZeroCopySource) error {
	height, eof := source.NextUint32()
	if eof {
		return fmt.Errorf("Waiting deserialize height error")
	}
	key, eof := source.NextString()
	if eof {
		return fmt.Errorf("Waiting deserialize key error")
	}
	ontTx, eof := source.NextString()
	if eof {
		return fmt.Errorf("Waiting deserialize ontTx error")
	}
	toChainId, eof := source.NextUint64()
	if eof {
		return fmt.Errorf("Waiting deserialize toChainId error")
	}
	rawSender, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("Waiting deserialize rawSender error")
	}
	args, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("Waiting deserialize args error")
	}
	rawContract, eof := source.NextVarBytes()
	if eof {
		return fmt.Errorf("Waiting deserialize rawContract error")
	}

	this.Height = height
	this.Key = key
	this.OntTx = ontTx
	this.ToChainId = toChainId
	this.Sender, _ = common2.AddressParseFromBytes(rawSender)
	this.Args = args
	this.FromContractAddress, _ = common2.AddressParseFromBytes(rawContract)
	return nil
}
