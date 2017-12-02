#include <stdio.h>
#include "init_scan.h"
#include "utils.h"
#include "tables.h"
#include <map>

int num_proc, num_file, num_socket, num_edge;
void emit_graph_detail(FILE *fp)
{
		tainted_inode_t *in, *in_tmp;
		tainted_cluster_t *tc, *tc_tmp;
		unit_list_t *el;
		unit_cluster_t *uc;
		process_table_t *pt;

		fprintf(fp, "/* num_proc %d, num_file %d, num_socket %d, num_edge %d\n", num_proc, num_file, num_socket, num_edge);

		fprintf(fp, "\nTainted Units:\n");
		HASH_ITER(hh, tainted_cluster, tc, tc_tmp) {
				fprintf(fp, "  pid %d, cluster %d, path %s\n", tc->id.pid, tc->id.clusterid, tc->path.c_str());
				fprintf(fp, "    cluster: ");
				pt = get_process_table(tc->id.pid);
				if(tc->id.clusterid == -1) {
						fprintf(fp, "all units");
				} else {
						HASH_FIND_INT(pt->unit_cluster, &(tc->id.clusterid), uc);
						DL_FOREACH(uc->list, el) {
								fprintf(fp, "%d-%d, ", el->id.tid, el->id.unitid);
						}
				}
				fprintf(fp, "\n");
		}

		fprintf(fp, "\nTainted Files:\n");
		HASH_ITER(hh, tainted_inode, in, in_tmp) {
				fprintf(fp, "  inode %ld (created_eid %ld), name %s\n", in->inode.inode, in->inode.created_eid, in->name.c_str());
		}

		fprintf(fp, "\nTainted Sockets:\n");
		
		for(map<string, int>::iterator it = tainted_socket.begin(); it != tainted_socket.end(); it++)
		{
				fprintf(fp, "  [%d] %s\n", it->second, it->first.c_str());
		}
		fprintf(fp, "*/\n");
}

void emit_graph(FILE *fp)
{
		tainted_inode_t *in, *in_tmp;
		tainted_cluster_t *tc, *tc_tmp;
		unit_list_t *el;
		unit_cluster_t *uc;
		process_table_t *pt;

		num_proc = num_file = num_socket = num_edge = 0;
		fprintf(fp, "digraph callgraph {\n\n");

		HASH_ITER(hh, tainted_cluster, tc, tc_tmp) {
				fprintf(fp, "node[shape=oval, label=\"%s\"] P%d_%d;\n", tc->path.c_str(), tc->id.pid, tc->id.clusterid);
				num_proc++;
		}
	
		fprintf(fp, "\n");
		HASH_ITER(hh, tainted_inode, in, in_tmp) {
				fprintf(fp, "node[shape=box, label=\"%s\"] F%ld_%ld;\n", in->name.c_str(), in->inode.inode, in->inode.created_eid);
				num_file++;
		}
	
		fprintf(fp, "\n");
		for(map<string, int>::iterator it = tainted_socket.begin(); it != tainted_socket.end(); it++)
		{
				fprintf(fp, "node[shape=diamond, label=\"%s\"] S%d;\n", it->first.c_str(), it->second);
				num_socket++;
		}

		fprintf(fp, "\n");
		for(set<string>::iterator it = edge_list.begin(); it != edge_list.end(); it++)
		{
				fprintf(fp, "%s;\n", (*it).c_str());
				num_edge++;
		}

		fprintf(fp, "}\n");
		printf("num_proc %d, num_file %d, num_socket %d, num_edge %d\n", num_proc, num_file, num_socket, num_edge);
}

