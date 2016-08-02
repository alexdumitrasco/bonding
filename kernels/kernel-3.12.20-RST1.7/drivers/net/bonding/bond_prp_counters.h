//----------------------------------------------------------------------------------------------------
#if defined( __tpxPRP_CommonCounters_definition_LIST )
//----------------------------------------------------------------------------------------------------
//	__tpxPRP_CommonCounters_definition( a )
//----------------------------------------------------------------------------------------------------
// Rx Counters
	__tpxPRP_CommonCounters_definition(    RxFrm)
	__tpxPRP_CommonCounters_definition(    RxFrmSupervision)
	__tpxPRP_CommonCounters_definition(    RxFrmOK)
// Rx Counters for ERRORs
	__tpxPRP_CommonCounters_definition(    RxErrors)
	__tpxPRP_CommonCounters_definition(    RxErrFrmIsNonLinear)
	__tpxPRP_CommonCounters_definition(    RxErrFrmTooShort)
	__tpxPRP_CommonCounters_definition(    RxErrUnknown)
// Tx Counters
	__tpxPRP_CommonCounters_definition(    TxFrm)
	__tpxPRP_CommonCounters_definition(    TxFrmOK)
// Tx Counters for ERRORs
	__tpxPRP_CommonCounters_definition(    TxErrors)
	__tpxPRP_CommonCounters_definition(    TxErrFrmIsNonLinear)
	__tpxPRP_CommonCounters_definition(    TxErrSkbCpyExpand)
	__tpxPRP_CommonCounters_definition(    TxErrSkbPutPadLngh)
	__tpxPRP_CommonCounters_definition(    TxErrSkbTailRoomPrpRct)
	__tpxPRP_CommonCounters_definition(    TxErrSkbPutPrpRct)
	__tpxPRP_CommonCounters_definition(    TxErrUnknown)

	__tpxPRP_CommonCounters_definition(    ErrReqToMACtable)
	__tpxPRP_CommonCounters_definition(    ColReqToMACtable)

//max numer off countersCommon, this counter must be last
	__tpxPRP_CommonCounters_definition(    MaxNumCountersCommon)
//----------------------------------------------------------------------------------------------------
#endif
//----------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------
#if defined( __tpxPRP_PerLanIDCounters_definition_LIST )
//----------------------------------------------------------------------------------------------------
//	__tpxPRP_PerLanIDCounters_definition(a)
//----------------------------------------------------------------------------------------------------
// Tx Counters
	__tpxPRP_PerLanIDCounters_definition(    TxFrmOnLan)
// Rx Counters
	__tpxPRP_PerLanIDCounters_definition(    RxFrmOnLan)
	__tpxPRP_PerLanIDCounters_definition(    RxFrmOkOnLan)
	__tpxPRP_PerLanIDCounters_definition(    RxFrmDrOnLan)
// Rx Counters
	__tpxPRP_PerLanIDCounters_definition(    RxPRPtrailerTrimedSkbOnLan)
	__tpxPRP_PerLanIDCounters_definition(    RxPRPtrailerNotTrimedSkbOnLan)
	__tpxPRP_PerLanIDCounters_definition(    RxErrNoPRPtrailerOnTrimedSkbOnLan)
// Rx Counters for ERRORs
	__tpxPRP_PerLanIDCounters_definition(    RxErrNoPRPtrailerOnLan)
	__tpxPRP_PerLanIDCounters_definition(    RxErrUnknownLanIDOnLan)
	__tpxPRP_PerLanIDCounters_definition(    RxErrWrongLanIDOnLan)
	__tpxPRP_PerLanIDCounters_definition(    RxErrWrongFrmSizeOnLan)
//max numer off countersPerLanID, this counter must be last
	__tpxPRP_PerLanIDCounters_definition(    MaxNumCountersPerLanID)
//----------------------------------------------------------------------------------------------------
#endif
//----------------------------------------------------------------------------------------------------
//----------------------------------------------------------------------------------------------------
