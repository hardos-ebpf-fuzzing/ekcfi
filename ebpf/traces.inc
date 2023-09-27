#ifdef __EBPF__

#define NR_CALLEES 21
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64 [NR_CALLEES]);
	__uint(max_entries, 1024);
} call_map SEC(".maps");

#else /* !__EBPF__ */

static struct {
	unsigned long long caller;
	unsigned long long callees[21];
} call_trace [98] = {
	{
		.caller = 0xffffffff81f3c393ULL,
		.callees = {
			[0] = 0xffffffff81f431b0ULL,
		},
	},
	{
		.caller = 0xffffffff8181113eULL,
		.callees = {
			[0] = 0xffffffff81830190ULL,
		},
	},
	{
		.caller = 0xffffffff810b9d83ULL,
		.callees = {
			[0] = 0xffffffff810c8780ULL,
		},
	},
	{
		.caller = 0xffffffff81663c94ULL,
		.callees = {
			[0] = 0xffffffff812326d0ULL,
		},
	},
	{
		.caller = 0xffffffff812ade04ULL,
		.callees = {
			[0] = 0xffffffff812aece0ULL,
		},
	},
	{
		.caller = 0xffffffff810bb379ULL,
		.callees = {
			[0] = 0xffffffff810c91c0ULL,
		},
	},
	{
		.caller = 0xffffffff8105b23bULL,
		.callees = {
			[0] = 0xffffffff8105b730ULL,
		},
	},
	{
		.caller = 0xffffffff81f6c45dULL,
		.callees = {
			[0] = 0xffffffff812954c0ULL,
		},
	},
	{
		.caller = 0xffffffff816679d7ULL,
		.callees = {
			[0] = 0xffffffff81233690ULL,
		},
	},
	{
		.caller = 0xffffffff818182d6ULL,
		.callees = {
			[0] = 0xffffffff81817af0ULL,
		},
	},
	{
		.caller = 0xffffffff8133815dULL,
		.callees = {
			[0] = 0xffffffff810443c0ULL,
		},
	},
	{
		.caller = 0xffffffff81664598ULL,
		.callees = {
			[0] = 0xffffffff812329b0ULL,
		},
	},
	{
		.caller = 0xffffffff81337efeULL,
		.callees = {
			[0] = 0xffffffff81044350ULL,
		},
	},
	{
		.caller = 0xffffffff81665119ULL,
		.callees = {
			[0] = 0xffffffff81232bb0ULL,
		},
	},
	{
		.caller = 0xffffffff8180bf1aULL,
		.callees = {
			[0] = 0xffffffff81810df0ULL,
		},
	},
	{
		.caller = 0xffffffff8183a523ULL,
		.callees = {
			[0] = 0xffffffff8183a0c0ULL,
		},
	},
	{
		.caller = 0xffffffff81316cc6ULL,
		.callees = {
			[0] = 0xffffffff8151ac70ULL,
		},
	},
	{
		.caller = 0xffffffff8130641eULL,
		.callees = {
			[0] = 0xffffffff8151d450ULL,
			[1] = 0xffffffff81394f60ULL,
			[2] = 0xffffffff81641b40ULL,
		},
	},
	{
		.caller = 0xffffffff8137a39cULL,
		.callees = {
			[0] = 0xffffffff8151ee50ULL,
		},
	},
	{
		.caller = 0xffffffff81665026ULL,
		.callees = {
			[0] = 0xffffffff81232b70ULL,
		},
	},
	{
		.caller = 0xffffffff8151cdb4ULL,
		.callees = {
			[0] = 0xffffffff81515a80ULL,
		},
	},
	{
		.caller = 0xffffffff8151d38eULL,
		.callees = {
			[0] = 0xffffffff8125ddb0ULL,
		},
	},
	{
		.caller = 0xffffffff81641dbeULL,
		.callees = {
			[0] = 0xffffffff81515a80ULL,
		},
	},
	{
		.caller = 0xffffffff813b9029ULL,
		.callees = {
			[0] = 0xffffffff81641510ULL,
		},
	},
	{
		.caller = 0xffffffff81831260ULL,
		.callees = {
			[0] = 0xffffffff8183a370ULL,
		},
	},
	{
		.caller = 0xffffffff813b63e4ULL,
		.callees = {
			[0] = 0xffffffff81641640ULL,
		},
	},
	{
		.caller = 0xffffffff81665c94ULL,
		.callees = {
			[0] = 0xffffffff81232e50ULL,
		},
	},
	{
		.caller = 0xffffffff81665d53ULL,
		.callees = {
			[0] = 0xffffffff81232e90ULL,
			[1] = 0xffffffff81663350ULL,
		},
	},
	{
		.caller = 0xffffffff8131eeb9ULL,
		.callees = {
			[0] = 0xffffffff8139cf90ULL,
		},
	},
	{
		.caller = 0xffffffff818145b8ULL,
		.callees = {
			[0] = 0xffffffff81830560ULL,
		},
	},
	{
		.caller = 0xffffffff81f8bc67ULL,
		.callees = {
			[0] = 0xffffffff810c8b80ULL,
		},
	},
	{
		.caller = 0xffffffff81394b6fULL,
		.callees = {
			[0] = 0xffffffff813382e0ULL,
		},
	},
	{
		.caller = 0xffffffff81307fe0ULL,
		.callees = {
			[0] = 0xffffffff81394c60ULL,
			[1] = 0xffffffff8151cab0ULL,
		},
	},
	{
		.caller = 0xffffffff8130709fULL,
		.callees = {
			[0] = 0xffffffff8151d520ULL,
		},
	},
	{
		.caller = 0xffffffff81337d12ULL,
		.callees = {
			[0] = 0xffffffff810442c0ULL,
		},
	},
	{
		.caller = 0xffffffff8131ee19ULL,
		.callees = {
			[0] = 0xffffffff8139cf90ULL,
		},
	},
	{
		.caller = 0xffffffff813088d0ULL,
		.callees = {
			[0] = 0xffffffff8180c040ULL,
		},
	},
	{
		.caller = 0xffffffff81394cf2ULL,
		.callees = {
			[0] = 0xffffffff81337c00ULL,
		},
	},
	{
		.caller = 0xffffffff81f3d3f8ULL,
		.callees = {
			[0] = 0xffffffff81f43490ULL,
		},
	},
	{
		.caller = 0xffffffff8180da30ULL,
		.callees = {
			[0] = 0xffffffff818306e0ULL,
		},
	},
	{
		.caller = 0xffffffff8126ab60ULL,
		.callees = {
			[0] = 0xffffffff8126a3b0ULL,
			[1] = 0xffffffff8126a7a0ULL,
		},
	},
	{
		.caller = 0xffffffff8133811bULL,
		.callees = {
			[0] = 0xffffffff810442c0ULL,
		},
	},
	{
		.caller = 0xffffffff8137a6d0ULL,
		.callees = {
			[0] = 0xffffffff8151c720ULL,
		},
	},
	{
		.caller = 0xffffffff81805864ULL,
		.callees = {
			[0] = 0xffffffff81809c10ULL,
		},
	},
	{
		.caller = 0xffffffff8181229aULL,
		.callees = {
			[0] = 0xffffffff81830190ULL,
		},
	},
	{
		.caller = 0xffffffff8115850aULL,
		.callees = {
			[0] = 0xffffffff816c3370ULL,
		},
	},
	{
		.caller = 0xffffffff81395072ULL,
		.callees = {
			[0] = 0xffffffff813a02f0ULL,
		},
	},
	{
		.caller = 0xffffffff813b9567ULL,
		.callees = {
			[0] = 0xffffffff816415b0ULL,
		},
	},
	{
		.caller = 0xffffffff812a5b2fULL,
		.callees = {
			[0] = 0xffffffff812aed80ULL,
			[1] = 0xffffffff8125cfe0ULL,
		},
	},
	{
		.caller = 0xffffffff8151d6a0ULL,
		.callees = {
			[0] = 0xffffffff81515a80ULL,
		},
	},
	{
		.caller = 0xffffffff81f6c961ULL,
		.callees = {
			[0] = 0xffffffff812954c0ULL,
		},
	},
	{
		.caller = 0xffffffff81321bbdULL,
		.callees = {
			[0] = 0xffffffff8180d7c0ULL,
		},
	},
	{
		.caller = 0xffffffff8125d762ULL,
		.callees = {
			[0] = 0xffffffff813b5780ULL,
		},
	},
	{
		.caller = 0xffffffff813b5849ULL,
		.callees = {
			[0] = 0xffffffff81641620ULL,
		},
	},
	{
		.caller = 0xffffffff813079c9ULL,
		.callees = {
			[0] = 0xffffffff81394ae0ULL,
		},
	},
	{
		.caller = 0xffffffff8151d4f9ULL,
		.callees = {
			[0] = 0xffffffff81515a80ULL,
		},
	},
	{
		.caller = 0xffffffff81665dc7ULL,
		.callees = {
			[0] = 0xffffffff81232e70ULL,
			[1] = 0xffffffff816632c0ULL,
		},
	},
	{
		.caller = 0xffffffff81666acaULL,
		.callees = {
			[0] = 0xffffffff81233230ULL,
		},
	},
	{
		.caller = 0xffffffff8166390cULL,
		.callees = {
			[0] = 0xffffffff81661ee0ULL,
			[1] = 0xffffffff812325b0ULL,
		},
	},
	{
		.caller = 0xffffffff812a5e19ULL,
		.callees = {
			[0] = 0xffffffff8125cfe0ULL,
		},
	},
	{
		.caller = 0xffffffff8130fcabULL,
		.callees = {
			[0] = 0xffffffff81640dd0ULL,
			[1] = 0xffffffff8127c3e0ULL,
			[2] = 0xffffffff8151a8e0ULL,
		},
	},
	{
		.caller = 0xffffffff8151cd88ULL,
		.callees = {
			[0] = 0xffffffff81515a80ULL,
		},
	},
	{
		.caller = 0xffffffff8183033dULL,
		.callees = {
			[0] = 0xffffffff8183a370ULL,
		},
	},
	{
		.caller = 0xffffffff812ab0e3ULL,
		.callees = {
			[0] = 0xffffffff8151d320ULL,
		},
	},
	{
		.caller = 0xffffffff8183a4eeULL,
		.callees = {
			[0] = 0xffffffff8183a0f0ULL,
		},
	},
	{
		.caller = 0xffffffff8180da80ULL,
		.callees = {
			[0] = 0xffffffff818112d0ULL,
		},
	},
	{
		.caller = 0xffffffff816660a7ULL,
		.callees = {
			[0] = 0xffffffff81232f70ULL,
		},
	},
	{
		.caller = 0xffffffff813951a1ULL,
		.callees = {
			[0] = 0xffffffff813383a0ULL,
		},
	},
	{
		.caller = 0xffffffff810a9705ULL,
		.callees = {
			[0] = 0xffffffff8130b6e0ULL,
		},
	},
	{
		.caller = 0xffffffff81663cf4ULL,
		.callees = {
			[0] = 0xffffffff812326f0ULL,
		},
	},
	{
		.caller = 0xffffffff8151d674ULL,
		.callees = {
			[0] = 0xffffffff81515a80ULL,
		},
	},
	{
		.caller = 0xffffffff81309281ULL,
		.callees = {
			[0] = 0xffffffff816422a0ULL,
		},
	},
	{
		.caller = 0xffffffff81665e39ULL,
		.callees = {
			[0] = 0xffffffff81232eb0ULL,
		},
	},
	{
		.caller = 0xffffffff8133800aULL,
		.callees = {
			[0] = 0xffffffff81044330ULL,
		},
	},
	{
		.caller = 0xffffffff81665c04ULL,
		.callees = {
			[0] = 0xffffffff81232e30ULL,
		},
	},
	{
		.caller = 0xffffffff812aab65ULL,
		.callees = {
			[0] = 0xffffffff81032a30ULL,
		},
	},
	{
		.caller = 0xffffffff8133819fULL,
		.callees = {
			[0] = 0xffffffff81044350ULL,
		},
	},
	{
		.caller = 0xffffffff813382adULL,
		.callees = {
			[0] = 0xffffffff81044330ULL,
		},
	},
	{
		.caller = 0xffffffff8132a112ULL,
		.callees = {
			[0] = 0xffffffff81394510ULL,
		},
	},
	{
		.caller = 0xffffffff8130b822ULL,
		.callees = {
			[0] = 0xffffffff8151d700ULL,
			[1] = 0xffffffff816429a0ULL,
			[2] = 0xffffffff81395130ULL,
		},
	},
	{
		.caller = 0xffffffff818366b2ULL,
		.callees = {
			[0] = 0xffffffff8183a0f0ULL,
		},
	},
	{
		.caller = 0xffffffff810db3e0ULL,
		.callees = {
			[0] = 0xffffffff810dba70ULL,
			[1] = 0xffffffff8108b450ULL,
		},
	},
	{
		.caller = 0xffffffff810bbad7ULL,
		.callees = {
			[0] = 0xffffffff810c9810ULL,
		},
	},
	{
		.caller = 0xffffffff810bb548ULL,
		.callees = {
			[0] = 0xffffffff8105b210ULL,
		},
	},
	{
		.caller = 0xffffffff81665b9eULL,
		.callees = {
			[0] = 0xffffffff81232e10ULL,
		},
	},
	{
		.caller = 0xffffffff81f77c7fULL,
		.callees = {
			[0] = 0xffffffff81296dc0ULL,
		},
	},
	{
		.caller = 0xffffffff812aedbeULL,
		.callees = {
			[0] = 0xffffffff81002650ULL,
		},
	},
	{
		.caller = 0xffffffff81663b0fULL,
		.callees = {
			[0] = 0xffffffff81663240ULL,
			[1] = 0xffffffff81232650ULL,
		},
	},
	{
		.caller = 0xffffffff812a5ad5ULL,
		.callees = {
			[0] = 0xffffffff8125d7c0ULL,
		},
	},
	{
		.caller = 0xffffffff816659ddULL,
		.callees = {
			[0] = 0xffffffff81232df0ULL,
		},
	},
	{
		.caller = 0xffffffff81319056ULL,
		.callees = {
			[0] = 0xffffffff81395aa0ULL,
		},
	},
	{
		.caller = 0xffffffff8105b770ULL,
		.callees = {
			[0] = 0xffffffff81068930ULL,
		},
	},
	{
		.caller = 0xffffffff81f83ca2ULL,
		.callees = {
			[0] = 0xffffffff81307100ULL,
			[1] = 0xffffffff813107a0ULL,
			[2] = 0xffffffff81147100ULL,
			[3] = 0xffffffff81320f70ULL,
			[4] = 0xffffffff8108a9d0ULL,
			[5] = 0xffffffff81032810ULL,
			[6] = 0xffffffff813056a0ULL,
			[7] = 0xffffffff812576c0ULL,
			[8] = 0xffffffff81308a80ULL,
			[9] = 0xffffffff812b0650ULL,
			[10] = 0xffffffff8109dc80ULL,
			[11] = 0xffffffff8109d0d0ULL,
			[12] = 0xffffffff81308c80ULL,
			[13] = 0xffffffff810816c0ULL,
			[14] = 0xffffffff81307960ULL,
			[15] = 0xffffffff81308b90ULL,
			[16] = 0xffffffff8102adb0ULL,
			[17] = 0xffffffff812ad270ULL,
			[18] = 0xffffffff812a8fc0ULL,
			[19] = 0xffffffff818459d0ULL,
			[20] = 0xffffffff81306e40ULL,
		},
	},
	{
		.caller = 0xffffffff81324551ULL,
		.callees = {
			[0] = 0xffffffff8139cfc0ULL,
		},
	},
	{
		.caller = 0xffffffff81f6c9c6ULL,
		.callees = {
			[0] = 0xffffffff812954c0ULL,
		},
	},
	{
		.caller = 0xffffffff81f8be0fULL,
		.callees = {
			[0] = 0xffffffff810c95c0ULL,
		},
	},
	{
		.caller = 0xffffffff81337d52ULL,
		.callees = {
			[0] = 0xffffffff810443c0ULL,
		},
	},
	{
		.caller = 0xffffffff818111d2ULL,
		.callees = {
			[0] = 0xffffffff81830540ULL,
		},
	},
};

#endif /* __EBPF__ */
