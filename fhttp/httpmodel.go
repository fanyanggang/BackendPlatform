package fhttp

import (
	"encoding/json"
)

type ResponseBody struct {
	DMErr    int         `json:"dm_error"`
	ErrorMsg string      `json:"error_msg"`
	Data     interface{} `json:"data"`
}

type DefaultResponseData struct {
}

func (b *ResponseBody) SetDMErr(errCode int) *ResponseBody {
	b.DMErr = errCode
	b.ErrorMsg = GetErrorMessage(errCode)
	return b
}

func (b *ResponseBody) SetData(data interface{}) *ResponseBody {
	b.Data = data
	return b
}

func (b *ResponseBody) Return() []byte {

	resp, _ := json.Marshal(&b)
	return resp
}

func DMError(errCode int) *ResponseBody {
	var resp ResponseBody
	resp.SetDMErr(errCode)
	//if resp.DMErr != common.ERROR_CODE_SUCCESS {
	// 防止出现Data为null的情况
	resp.Data = DefaultResponseData{}
	//}
	return &resp
}

func Success(data interface{}) *ResponseBody {
	return DMError(ERROR_CODE_SUCCESS).SetData(data)
}
