#pragma once

#include"NativeStructs10.h"
#include<ntifs.h>

TABLE_SEARCH_RESULT
MiFindNodeOrParent(
    IN PMM_AVL_TABLE Table,
    IN ULONG_PTR StartingVpn,
    OUT PMMADDRESS_NODE* NodeOrParent
);