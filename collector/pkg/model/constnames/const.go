package constnames

const (
	ReadEvent     = "read"
	WriteEvent    = "write"
	ReadvEvent    = "readv"
	WritevEvent   = "writev"
	PReadEvent    = "pread"
	PWriteEvent   = "pwrite"
	PReadvEvent   = "preadv"
	PWritevEvent  = "pwritev"
	SendToEvent   = "sendto"
	RecvFromEvent = "recvfrom"
	SendMsgEvent  = "sendmsg"
	SendMMsgEvent = "sendmmsg"
	RecvMsgEvent  = "recvmsg"
	ConnectEvent  = "connect"

	TcpCloseEvent          = "tcp_close"
	TcpRcvEstablishedEvent = "tcp_rcv_established"
	TcpDropEvent           = "tcp_drop"
	TcpRetransmitSkbEvent  = "tcp_retransmit_skb"
	TcpConnectEvent        = "tcp_connect"
	TcpSetStateEvent       = "tcp_set_state"

	CpuEvent           = "cpu_event"
	JavaFutexInfo      = "java_futex_info"
	TransactionIdEvent = "apm_trace_id_event"
	SpanEvent          = "apm_span_event"
	OtherEvent         = "other"

	ReadXEventType     = 7
	WriteXEventType    = 9
	ReadvXEventType    = 117
	WritevXEventType   = 119
	SendToXEventType   = 31
	RecvFromXEventType = 35
	SendMsgXEventType  = 49

	SendMMsgXEventType          = 51
	RecvMsgXEventType           = 53
	ConnectXEventType           = 23
	TcpCloseEEventType          = 328
	TcpRcvEstablishedEEventType = 326
	TcpDropEEventType           = 330
	TcpRetransmitSkbEEventType  = 332
	TcpConnectXEventType        = 335
	TcpSetStateEEventType       = 336

	ProcessExitEvent = "procexit"
	GrpcUprobeEvent  = "grpc_uprobe"
	// NetRequestMetricGroupName is used for dataGroup generated from networkAnalyzer.
	NetRequestMetricGroupName = "net_request_metric_group"
	// SingleNetRequestMetricGroup stands for the dataGroup with abnormal status.
	SingleNetRequestMetricGroup = "single_net_request_metric_group"
	// AggregatedNetRequestMetricGroup stands for the dataGroup after aggregation.
	AggregatedNetRequestMetricGroup = "aggregated_net_request_metric_group"

	CameraEventGroupName = "camera_event_group"

	TcpRttMetricGroupName        = "tcp_rtt_metric_group"
	TcpRetransmitMetricGroupName = "tcp_retransmit_metric_group"
	TcpDropMetricGroupName       = "tcp_drop_metric_group"
	NodeMetricGroupName          = "node_metric_metric_group"
	TcpConnectMetricGroupName    = "tcp_connect_metric_group"
)
