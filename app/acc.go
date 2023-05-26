package app

import (
	"fmt"
	"github.com/bianjieai/iritamod/modules/perm"
	"github.com/bianjieai/iritamod/modules/perm/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	gogotypes "github.com/gogo/protobuf/types"
	tokentypes "github.com/irisnet/irismod/modules/token/types"
)

func (app *IritaApp) extendInitData(ctx sdk.Context) {
	var rootAdmin = "iaa1hanchhmz9hskjvusfvjzkhzgh8s5sq6wvpdapl"
	var canStayAccounts = map[string]bool{
		"iaa15j28whwhxt64x86w9gxpg0cqz9tpnvxjyyqj2l": true,
		"iaa16nnc9yw6hc8f62rpwsv2vhde3qkfunuecpd7r7": true,
		"iaa1rs4ydc9ftcmym7urul9uye0mer57uvs0z8hdjc": true,
		"iaa1rha7mx5jatel79u5welcxt2yxq4rmc0lyk5fyt": true,
		"iaa190u6swlwv63w3z5su8f0n7ses94pvtnn8mxlw9": true,
	}

	cdc := app.appCodec
	permStore := ctx.KVStore(app.keys[perm.StoreKey])
	permIter := sdk.KVStorePrefixIterator(permStore, types.AuthKey)
	defer permIter.Close()

	for ; permIter.Valid(); permIter.Next() {
		var role gogotypes.Int32Value
		cdc.MustUnmarshal(permIter.Value(), &role)
		account := sdk.AccAddress(permIter.Key()[len(types.AuthKey):])
		toWrite := fmt.Sprintf("%s:%s", account.String(), types.Auth(role.Value).Roles())
		if types.Auth(role.Value).Access(
			types.RoleRootAdmin.Auth() |
				types.RolePermAdmin.Auth() |
				types.RoleBlacklistAdmin.Auth() |
				types.RoleIDAdmin.Auth() |
				types.RoleBaseM1Admin.Auth() |
				types.RoleNodeAdmin.Auth() |
				types.RoleParamAdmin.Auth() |
				types.RolePowerUserAdmin.Auth() |
				types.RolePlatformUser.Auth() |
				types.RoleRelayerUser.Auth(),
		) {
			if canStayAccounts[account.String()] {
				continue
			}
			app.permKeeper.DeleteAuth(ctx, account)
			err := app.permKeeper.Block(ctx, account)
			if err != nil {
				panic(err)
			}
			app.Logger().Info("Auth removed", "origin", toWrite)
		}
	}
	rootAdminAcc, err := sdk.AccAddressFromBech32(rootAdmin)
	if err != nil {
		panic(err)
	}
	app.permKeeper.SetAuth(ctx, rootAdminAcc, types.RoleRootAdmin.Auth())

	tokenStore := ctx.KVStore(app.keys[tokentypes.StoreKey])
	tokenIter := sdk.KVStorePrefixIterator(tokenStore, tokentypes.PrefixTokenForSymbol)
	defer tokenIter.Close()
	for ; tokenIter.Valid(); tokenIter.Next() {
		t := tokentypes.Token{}
		cdc.MustUnmarshal(tokenIter.Value(), &t)
		err = app.tokenKeeper.TransferTokenOwner(ctx, t.Symbol, t.GetOwner(), rootAdminAcc)
		if err != nil {
			panic(err)
		}
	}
	return
}
