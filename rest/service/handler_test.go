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
	"bytes"
	"encoding/hex"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
	"github.com/polynetwork/btc-vendor-tools/config"
	"github.com/polynetwork/btc-vendor-tools/observer"
	"github.com/polynetwork/btc-vendor-tools/rest/http/restful"
	"github.com/polynetwork/btc-vendor-tools/signer"
	"github.com/polynetwork/btc-vendor-tools/utils"
	"testing"
)

var (
	redeem    = "5521023ac710e73e1410718530b2686ce47f12fa3c470a9eb6085976b70b01c64c9f732102c9dc4d8f419e325bbef0fe039ed6feaf2079a2ef7b27336ddb79be2ea6e334bf2102eac939f2f0873894d8bf0ef2f8bbdd32e4290cbf9632b59dee743529c0af9e802103378b4a3854c88cca8bfed2558e9875a144521df4a75ab37a206049ccef12be692103495a81957ce65e3359c114e6c2fe9f97568be491e3f24d6fa66cc542e360cd662102d43e29299971e802160a92cfcd4037e8ae83fb8f6af138684bebdc5686f3b9db21031e415c04cbc9b81fbee6e04d8c902e8f61109a2c9883a959ba528c52698c055a57ae"
	usignedTx = "01000000015ef067df7af576fa5b43bb7e99846c970af7e998cf060c9942920883a515cc6c0000000000ffffffff01401f00000000000017a91487a9652e9b396545598c0fc72cb5a98848bf93d38700000000"
)

func TestService_SignTx(t *testing.T) {
	config.BtcNetParam = &chaincfg.TestNet3Params
	rb, _ := hex.DecodeString(redeem)
	sgr, err := signer.NewSigner("/Users/zou/go/src/github.com/ontio/btc-vendor-tools/privk",
		nil, nil, nil, rb)
	if err != nil {
		t.Fatal(err)
	}

	serv := NewService(sgr)
	restServer := restful.InitRestServer(serv, 50071)
	go restServer.Start()

	obc := observer.NewObCli("0.0.0.0:50071")

	txb, _ := hex.DecodeString(usignedTx)
	mtx := wire.NewMsgTx(wire.TxVersion)
	mtx.BtcDecode(bytes.NewBuffer(txb), wire.ProtocolVersion, wire.LatestEncoding)

	if err := obc.SendToSign(&utils.ToSignItem{
		Amts: []uint64{1},
		Mtx:  mtx,
	}); err != nil {
		t.Fatal(err)
	}
}
