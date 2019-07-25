package main

import (
	"encoding/hex"
	"fmt"
	"github.com/516108736/accountGen/account"
)

func main()  {
	account,err:=account.CreatRandomIdentity()
	if err!=nil{
		panic(err)
	}
	fmt.Println("公钥",account.GetRecipient().String())
	fmt.Println("密码",hex.EncodeToString(account.GetKey().Bytes()))
}
