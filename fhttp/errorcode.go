package fhttp

const (
	//
	// 通用错误 [0,699]
	//
	ERROR_CODE_SUCCESS  int = 0 // 操作成功
	ERROR_LOGIN_SUCCESS int = 1 // 正常登陆用户
	//
	// 调用端引发的错误 [400,499]
	ERROR_CODE_CLIENT_ERROR     int = 499 // 请求参数错误（调用端的参数有问题）
	ERROR_CODE_ILLEGAL_INPUT    int = 401 // 输入非法（包含不允许的字符、超长、过短等）
	ERROR_CODE_ILLE_USER        int = 402 // 非法用户
	ERROR_CODE_FUll_USER        int = 403 // 报名人数满员
	ERROR_CODE_HAS_PAY          int = 404 // 已经支付
	ERROR_CODE_HAS_ADDPUBG      int = 405 // 已经报名
	ERROR_CODE_DATA_INEXISTENCE int = 406 // 已经报名
	ERROR_CODE_NO_TEAM_NUM      int = 407 // 没有添加队名
	ERROR_CODE_NO_NICKNAME      int = 408 // 没有添加昵称

	//
	// server端引发的错误 [500,599]
	ERROR_CODE_SERVER_ERROR               int = 500 // 服务器遇到了一个未曾预料的状况，导致了它无法完成对请求的处理。一般来说，这个问题都会在服务器端的源代码出现错误时出现。
	ERROR_CODE_NOT_IMPLEMENTED            int = 501 // 服务器不支持当前请求所需要的某个功能。当服务器无法识别请求的方法，并且无法支持其对任何资源的请求。
	ERROR_CODE_BAD_GATEWAY                int = 502 // 作为网关或者代理工作的服务器尝试执行请求时，从上游服务器接收到无效的响应。
	ERROR_CODE_SERVICE_UNAVAILABLE        int = 503 // 由于临时的服务器维护或者过载，服务器当前无法处理请求。这个状况是临时的，并且将在一段时间以后恢复。如果能够预计延迟时间，那么响应中可以包含一个 Retry-After 头用以标明这个延迟时间。如果没有给出这个 Retry-After 信息，那么客户端应当以处理500响应的方式处理它。
	ERROR_CODE_GATEWAY_TIMEOUT            int = 504 // 作为网关或者代理工作的服务器尝试执行请求时，未能及时从上游服务器（URI标识出的服务器，例如HTTP、FTP、LDAP）或者辅助服务器（例如DNS）收到响应（某些代理服务器在DNS查询超时时会返回400或者500错误）。
	ERROR_CODE_HTTP_VERSION_NOT_SUPPORTED int = 505 // 服务器不支持，或者拒绝支持在请求中使用的 HTTP 版本。这暗示着服务器不能或不愿使用与客户端相同的版本。响应中应当包含一个描述了为何版本不被支持以及服务器支持哪些协议的实体。
	ERROR_CODE_VARIANT_ALSO_NEGOTIATES    int = 506 // 由《透明内容协商协议》（RFC 2295）扩展，代表服务器存在内部配置错误：被请求的协商变元资源被配置为在透明内容协商中使用自己，因此在一个协商处理中不是一个合适的重点。
	ERROR_CODE_INSUFFICIENT_STORAGE       int = 507 // 服务器无法存储完成请求所必须的内容。这个状况被认为是临时的。WebDAV (RFC 4918)
	ERROR_CODE_BANDWIDTH_LIMIT_EXCEEDED   int = 509 // 服务器达到带宽限制。这不是一个官方的状态码，但是仍被广泛使用。
	ERROR_CODE_NOT_EXTENDED               int = 510 // 获取资源所需要的策略并没有被满足。（RFC 2774）
	ERROR_CODE_THREE_WAY_INTERFACE        int = 520 // 服务器请求三方依赖接口出错

	ERROR_CODE_ACCOUNT_NOT_ENOUGH int = 600 // 用户余额不足
	ERROR_CODE_DATA_NOT_EXIST     int = 601 // 数据不存在

)

func GetErrorMessage(errCode int) string {
	switch errCode {
	case ERROR_CODE_SUCCESS:
		return "操作成功"
	case ERROR_CODE_CLIENT_ERROR:
		return "请求参数错误"
	case ERROR_CODE_SERVER_ERROR:
		return "内部系统错误"
	case ERROR_LOGIN_SUCCESS:
		return "正常登陆用户"
	case ERROR_CODE_ACCOUNT_NOT_ENOUGH:
		return "用户账户余额不足"
	case ERROR_CODE_DATA_NOT_EXIST:
		return "数据不存在"
	case ERROR_CODE_ILLE_USER:
		return "用户信息错误"
	case ERROR_CODE_FUll_USER:
		return "报名人数满员"
	case ERROR_CODE_HAS_PAY:
		return "已经支付"
	case ERROR_CODE_HAS_ADDPUBG:
		return "已经报名"
	case ERROR_CODE_DATA_INEXISTENCE:
		return "数据不存在"
	case ERROR_CODE_NO_TEAM_NUM:
		return "没有添加队名"
	case ERROR_CODE_NO_NICKNAME:
		return "没有添加昵称"
	}

	if errCode <= 499 {
		return "参数错误"
	}
	if errCode >= 800 && errCode <= 899 {
		return "操作失败，请稍后再试"
	}
	if errCode >= 500 && errCode < 10000 {
		return "内部系统错误"
	}

	return "业务处理异常"
}
