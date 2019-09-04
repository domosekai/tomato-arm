#include <xtables.h>

static struct xtables_target removect_target = {
	.family         = NFPROTO_IPV4,
	.name           = "REMOVECT",
	.version        = XTABLES_VERSION,
	.size           = XT_ALIGN(0),
	.userspacesize  = XT_ALIGN(0),
};

void _init(void)
{
	xtables_register_target(&removect_target);
}
