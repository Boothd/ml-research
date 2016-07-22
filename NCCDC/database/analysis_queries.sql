select min(time), max(time) from pcap_data;

select * from pcap_data
where time = (select min(time) from pcap_data)
or time = (select max(time) from pcap_data);


select
	dst,
	dst_ip,
	count(distinct dst_port) num_ports,
	src,
	src_ip,
	count(*) num_connections,
	min(time) first_connection,
	max(time) last_connection,
	sum(case when syn = 1 and ack = 0 and rst = 0 then 1 else 0 end) num_syn,
	sum(case when ack = 1 and syn = 0 and rst = 0 then 1 else 0 end) num_ack,
	sum(case when syn = 1 and ack = 1 then 1 else 0 end) num_synack,
	sum(case when rst = 1 and ack = 0 and syn = 0 then 1 else 0 end) num_rst,
	sum(case when rst = 1 and ack = 1 then 1 else 0 end) num_rstack,
	sum(case when protocol = 1 then 1 else 0 end) num_icmp,
	sum(case when protocol = 6 then 1 else 0 end) num_tcp,
	sum(case when protocol = 17 then 1 else 0 end) num_udp
from pcap_data
group by dst, dst_ip, src, src_ip
;


select
	dst,
	dst_ip,
	count(distinct dst_port) num_ports,
	count(*) num_connections,
	count(distinct src) num_sources,
	sum(case when protocol = 1 then 1 else 0 end) num_icmp,
	sum(case when protocol = 6 then 1 else 0 end) num_tcp,
	sum(case when protocol = 17 then 1 else 0 end) num_udp
from pcap_data
group by dst, dst_ip
;


select * from (
	(
		select ts datetime, src_ip as attackerip, src as attackeripint, src_port as attackerport, dst_ip as victimip, dst as victimipint, dst_port as victimport, "Attacker -> Victim" as direction, flags, syn, ack, rst from pcap_data
		where src = inet_aton('10.10.10.250') -- attacker ip
		and dst = inet_aton('172.16.10.253') -- victim ip
		and protocol = 6 -- TCP
	)
	union
	(
		select ts datetime, dst_ip as attackerip, dst as attackeripint, dst_port as attackerport, src_ip as victimip, src as victimipint, src_port as victimport, "Victim -> Attacker" as direction, flags, syn, ack, rst from pcap_data
		where dst = inet_aton('10.10.10.250') -- attacker ip
		and src = inet_aton('172.16.10.253') -- victim ip
		and protocol = 6 -- TCP
	)
) dialogues 
where victimport = 3301
order by victimport, datetime
;
