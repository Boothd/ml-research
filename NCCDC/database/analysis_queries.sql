select min(time), max(time) from pcap_data;

select * from pca_data
where time = (select min(time) from pcap_data)
or time = (select max(time) from pcap_data);


select
	dst,
	dst_ip,
    src,
    src_ip,
    count(distinct dst_port) num_ports,
	count(*) num_connections,
	min(time) first_connection,
    max(time) last_connection,
    count(distinct src_port) num_src_ports,
	sum(case when syn = 1 and ack = 0 then 1 else 0 end) num_syn,
	sum(case when ack = 1 and syn = 0 and rst = 0 then 1 else 0 end) num_ack,
	sum(case when syn = 1 and ack = 1 then 1 else 0 end) num_synack,
	sum(case when rst = 1 and ack = 0 then 1 else 0 end) num_rst,
	sum(case when rst = 1 and ack = 1 then 1 else 0 end) num_rstack,
    sum(case when protocol = 1 then 1 else 0 end) num_icmp,
    sum(case when protocol = 6 then 1 else 0 end) num_tcp,
    sum(case when protocol = 17 then 1 else 0 end) num_udp
from pcap_data
/*where dst = inet_aton('172.16.10.253')*/
group by dst, dst_ip, src, src_ip
;


select
	dst,
	dst_ip,
/*    src,
    src_ip,*/
    count(distinct dst_port) num_ports,
	count(*) num_connections,
/*	min(time) first_connection,
    max(time) last_connection,
    count(distinct src_port) num_src_ports,*/
	count(distinct src) num_sources,
/*	sum(case when syn = 1 and ack = 0 then 1 else 0 end) num_syn,
	sum(case when ack = 1 and syn = 0 and rst = 0 then 1 else 0 end) num_ack,
	sum(case when syn = 1 and ack = 1 then 1 else 0 end) num_synack,
	sum(case when rst = 1 and ack = 0 then 1 else 0 end) num_rst,
	sum(case when rst = 1 and ack = 1 then 1 else 0 end) num_rstack,*/
    sum(case when protocol = 1 then 1 else 0 end) num_icmp,
    sum(case when protocol = 6 then 1 else 0 end) num_tcp,
    sum(case when protocol = 17 then 1 else 0 end) num_udp
from pcap_data
group by dst, dst_ip /*, src, src_ip*/
;