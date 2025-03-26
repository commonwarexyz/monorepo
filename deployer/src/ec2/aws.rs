//! AWS EC2 SDK function wrappers

use super::METRICS_PORT;
use crate::ec2::{
    utils::{exact_cidr, DEPLOYER_MAX_PORT, DEPLOYER_MIN_PORT, DEPLOYER_PROTOCOL, RETRY_INTERVAL},
    PortConfig,
};
use aws_config::BehaviorVersion;
pub use aws_config::Region;
use aws_sdk_ec2::error::BuildError;
use aws_sdk_ec2::primitives::Blob;
use aws_sdk_ec2::types::{
    BlockDeviceMapping, EbsBlockDevice, Filter, InstanceStateName, ResourceType, SecurityGroup,
    SummaryStatus, Tag, TagSpecification, VpcPeeringConnectionStateReasonCode,
};
pub use aws_sdk_ec2::types::{InstanceType, IpPermission, IpRange, UserIdGroupPair, VolumeType};
use aws_sdk_ec2::{Client as Ec2Client, Error as Ec2Error};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::time::sleep;

/// Creates an EC2 client for the specified AWS region
pub async fn create_ec2_client(region: Region) -> Ec2Client {
    let config = aws_config::defaults(BehaviorVersion::v2024_03_28())
        .region(region)
        .load()
        .await;
    Ec2Client::new(&config)
}

/// Imports an SSH public key into the specified region
pub async fn import_key_pair(
    client: &Ec2Client,
    key_name: &str,
    public_key: &str,
) -> Result<(), Ec2Error> {
    let blob = Blob::new(public_key.as_bytes());
    client
        .import_key_pair()
        .key_name(key_name)
        .public_key_material(blob)
        .send()
        .await?;
    Ok(())
}

/// Deletes an SSH key pair from the specified region
pub async fn delete_key_pair(client: &Ec2Client, key_name: &str) -> Result<(), Ec2Error> {
    client.delete_key_pair().key_name(key_name).send().await?;
    Ok(())
}

/// Finds the latest Ubuntu 22.04 ARM64 AMI in the region
pub async fn find_latest_ami(client: &Ec2Client) -> Result<String, Ec2Error> {
    let resp = client
        .describe_images()
        .filters(
            Filter::builder()
                .name("name")
                .values("ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-arm64-server-*")
                .build(),
        )
        .filters(
            Filter::builder()
                .name("root-device-type")
                .values("ebs")
                .build(),
        )
        .owners("099720109477") // Canonical's AWS account ID
        .send()
        .await?;
    let mut images = resp.images.unwrap_or_default();
    if images.is_empty() {
        return Err(Ec2Error::from(BuildError::other(
            "No matching AMI found".to_string(),
        )));
    }
    images.sort_by(|a, b| b.creation_date().cmp(&a.creation_date()));
    let latest_ami = images[0].image_id().unwrap();
    Ok(latest_ami.to_string())
}

/// Creates a VPC with the specified CIDR block and tag
pub async fn create_vpc(
    client: &Ec2Client,
    cidr_block: &str,
    tag: &str,
) -> Result<String, Ec2Error> {
    let resp = client
        .create_vpc()
        .cidr_block(cidr_block)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::Vpc)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    Ok(resp.vpc.unwrap().vpc_id.unwrap())
}

/// Creates an Internet Gateway and attaches it to the specified VPC
pub async fn create_and_attach_igw(
    client: &Ec2Client,
    vpc_id: &str,
    tag: &str,
) -> Result<String, Ec2Error> {
    let igw_resp = client
        .create_internet_gateway()
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::InternetGateway)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    let igw_id = igw_resp
        .internet_gateway
        .unwrap()
        .internet_gateway_id
        .unwrap();
    client
        .attach_internet_gateway()
        .internet_gateway_id(&igw_id)
        .vpc_id(vpc_id)
        .send()
        .await?;
    Ok(igw_id)
}

/// Creates a route table for the VPC and sets up a default route to the Internet Gateway
pub async fn create_route_table(
    client: &Ec2Client,
    vpc_id: &str,
    igw_id: &str,
    tag: &str,
) -> Result<String, Ec2Error> {
    let rt_resp = client
        .create_route_table()
        .vpc_id(vpc_id)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::RouteTable)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    let rt_id = rt_resp.route_table.unwrap().route_table_id.unwrap();
    client
        .create_route()
        .route_table_id(&rt_id)
        .destination_cidr_block("0.0.0.0/0")
        .gateway_id(igw_id)
        .send()
        .await?;
    Ok(rt_id)
}

/// Creates a subnet within the VPC and associates it with the route table
pub async fn create_subnet(
    client: &Ec2Client,
    vpc_id: &str,
    route_table_id: &str,
    subnet_cidr: &str,
    availability_zone: &str,
    tag: &str,
) -> Result<String, Ec2Error> {
    let subnet_resp = client
        .create_subnet()
        .vpc_id(vpc_id)
        .cidr_block(subnet_cidr)
        .availability_zone(availability_zone)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::Subnet)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    let subnet_id = subnet_resp.subnet.unwrap().subnet_id.unwrap();
    client
        .associate_route_table()
        .route_table_id(route_table_id)
        .subnet_id(&subnet_id)
        .send()
        .await?;
    Ok(subnet_id)
}

/// Creates a security group for the monitoring instance with access from the deployer IP
pub async fn create_security_group_monitoring(
    client: &Ec2Client,
    vpc_id: &str,
    deployer_ip: &str,
    tag: &str,
) -> Result<String, Ec2Error> {
    let sg_resp = client
        .create_security_group()
        .group_name(tag)
        .description("Security group for monitoring instance")
        .vpc_id(vpc_id)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::SecurityGroup)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    let sg_id = sg_resp.group_id.unwrap();
    client
        .authorize_security_group_ingress()
        .group_id(&sg_id)
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol(DEPLOYER_PROTOCOL)
                .from_port(DEPLOYER_MIN_PORT)
                .to_port(DEPLOYER_MAX_PORT)
                .ip_ranges(IpRange::builder().cidr_ip(exact_cidr(deployer_ip)).build())
                .build(),
        )
        .send()
        .await?;
    Ok(sg_id)
}

/// Creates a security group for binary instances with access from deployer, monitoring, and custom ports
pub async fn create_security_group_binary(
    client: &Ec2Client,
    vpc_id: &str,
    deployer_ip: &str,
    monitoring_ip: &str,
    tag: &str,
    ports: &[PortConfig],
) -> Result<String, Ec2Error> {
    let sg_resp = client
        .create_security_group()
        .group_name(format!("{}-binary", tag))
        .description("Security group for binary instances")
        .vpc_id(vpc_id)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::SecurityGroup)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    let sg_id = sg_resp.group_id.unwrap();
    let mut builder = client
        .authorize_security_group_ingress()
        .group_id(&sg_id)
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol(DEPLOYER_PROTOCOL)
                .from_port(DEPLOYER_MIN_PORT)
                .to_port(DEPLOYER_MAX_PORT)
                .ip_ranges(IpRange::builder().cidr_ip(exact_cidr(deployer_ip)).build())
                .build(),
        )
        .ip_permissions(
            IpPermission::builder()
                .ip_protocol("tcp")
                .from_port(METRICS_PORT as i32)
                .to_port(METRICS_PORT as i32)
                .ip_ranges(
                    IpRange::builder()
                        .cidr_ip(exact_cidr(monitoring_ip))
                        .build(),
                )
                .build(),
        );
    for port in ports {
        builder = builder.ip_permissions(
            IpPermission::builder()
                .ip_protocol(&port.protocol)
                .from_port(port.port as i32)
                .to_port(port.port as i32)
                .ip_ranges(IpRange::builder().cidr_ip(&port.cidr).build())
                .build(),
        );
    }
    builder.send().await?;
    Ok(sg_id)
}

/// Launches EC2 instances with specified configurations
#[allow(clippy::too_many_arguments)]
pub async fn launch_instances(
    client: &Ec2Client,
    ami_id: &str,
    instance_type: InstanceType,
    storage_size: i32,
    storage_class: VolumeType,
    key_name: &str,
    subnet_id: &str,
    sg_id: &str,
    count: i32,
    name: &str,
    tag: &str,
) -> Result<Vec<String>, Ec2Error> {
    let resp = client
        .run_instances()
        .image_id(ami_id)
        .instance_type(instance_type)
        .key_name(key_name)
        .min_count(count)
        .max_count(count)
        .network_interfaces(
            aws_sdk_ec2::types::InstanceNetworkInterfaceSpecification::builder()
                .associate_public_ip_address(true)
                .device_index(0)
                .subnet_id(subnet_id)
                .groups(sg_id)
                .build(),
        )
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::Instance)
                .set_tags(Some(vec![
                    Tag::builder().key("deployer").value(tag).build(),
                    Tag::builder().key("name").value(name).build(),
                ]))
                .build(),
        )
        .block_device_mappings(
            BlockDeviceMapping::builder()
                .device_name("/dev/sda1")
                .ebs(
                    EbsBlockDevice::builder()
                        .volume_size(storage_size)
                        .volume_type(storage_class)
                        .delete_on_termination(true)
                        .build(),
                )
                .build(),
        )
        .send()
        .await?;
    Ok(resp
        .instances
        .unwrap()
        .into_iter()
        .map(|i| i.instance_id.unwrap())
        .collect())
}

/// Waits for instances to reach the "running" state and returns their public IPs
pub async fn wait_for_instances_running(
    client: &Ec2Client,
    instance_ids: &[String],
) -> Result<Vec<String>, Ec2Error> {
    loop {
        // Ask for instance details
        let Ok(resp) = client
            .describe_instances()
            .set_instance_ids(Some(instance_ids.to_vec()))
            .send()
            .await
        else {
            sleep(RETRY_INTERVAL).await;
            continue;
        };

        // Confirm all are running
        let reservations = resp.reservations.unwrap();
        let instances = reservations[0].instances.as_ref().unwrap();
        if !instances.iter().all(|i| {
            i.state.as_ref().unwrap().name.as_ref().unwrap() == &InstanceStateName::Running
        }) {
            sleep(RETRY_INTERVAL).await;
            continue;
        }
        return Ok(instances
            .iter()
            .map(|i| i.public_ip_address.as_ref().unwrap().clone())
            .collect());
    }
}

pub async fn wait_for_instances_ready(
    client: &Ec2Client,
    instance_ids: &[String],
) -> Result<(), Ec2Error> {
    loop {
        // Ask for instance status
        let Ok(resp) = client
            .describe_instance_status()
            .set_instance_ids(Some(instance_ids.to_vec()))
            .include_all_instances(true) // Include instances regardless of state
            .send()
            .await
        else {
            sleep(RETRY_INTERVAL).await;
            continue;
        };

        // Confirm all are ready
        let statuses = resp.instance_statuses.unwrap_or_default();
        let all_ready = statuses.iter().all(|s| {
            s.instance_state.as_ref().unwrap().name.as_ref().unwrap() == &InstanceStateName::Running
                && s.system_status.as_ref().unwrap().status.as_ref().unwrap() == &SummaryStatus::Ok
                && s.instance_status.as_ref().unwrap().status.as_ref().unwrap()
                    == &SummaryStatus::Ok
        });
        if !all_ready {
            sleep(RETRY_INTERVAL).await;
            continue;
        }
        return Ok(());
    }
}

/// Retrieves the private IP address of an instance
pub async fn get_private_ip(client: &Ec2Client, instance_id: &str) -> Result<String, Ec2Error> {
    let resp = client
        .describe_instances()
        .instance_ids(instance_id)
        .send()
        .await?;
    let reservations = resp.reservations.unwrap();
    let instance = &reservations[0].instances.as_ref().unwrap()[0];
    Ok(instance.private_ip_address.as_ref().unwrap().clone())
}

/// Creates a VPC peering connection between two VPCs
pub async fn create_vpc_peering_connection(
    client: &Ec2Client,
    requester_vpc_id: &str,
    peer_vpc_id: &str,
    peer_region: &str,
    tag: &str,
) -> Result<String, Ec2Error> {
    let resp = client
        .create_vpc_peering_connection()
        .vpc_id(requester_vpc_id)
        .peer_vpc_id(peer_vpc_id)
        .peer_region(peer_region)
        .tag_specifications(
            TagSpecification::builder()
                .resource_type(ResourceType::VpcPeeringConnection)
                .tags(Tag::builder().key("deployer").value(tag).build())
                .build(),
        )
        .send()
        .await?;
    Ok(resp
        .vpc_peering_connection
        .unwrap()
        .vpc_peering_connection_id
        .unwrap())
}

/// Waits for a VPC peering connection to reach the "pending-acceptance" state
pub async fn wait_for_vpc_peering_connection(
    client: &Ec2Client,
    peer_id: &str,
) -> Result<(), Ec2Error> {
    loop {
        if let Ok(resp) = client
            .describe_vpc_peering_connections()
            .vpc_peering_connection_ids(peer_id)
            .send()
            .await
        {
            if let Some(connections) = resp.vpc_peering_connections {
                if let Some(connection) = connections.first() {
                    if connection.status.as_ref().unwrap().code
                        == Some(VpcPeeringConnectionStateReasonCode::PendingAcceptance)
                    {
                        return Ok(());
                    }
                }
            }
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// Accepts a VPC peering connection in the peer region
pub async fn accept_vpc_peering_connection(
    client: &Ec2Client,
    peer_id: &str,
) -> Result<(), Ec2Error> {
    client
        .accept_vpc_peering_connection()
        .vpc_peering_connection_id(peer_id)
        .send()
        .await?;
    Ok(())
}

/// Adds a route to a route table for VPC peering
pub async fn add_route(
    client: &Ec2Client,
    route_table_id: &str,
    destination_cidr: &str,
    peer_id: &str,
) -> Result<(), Ec2Error> {
    client
        .create_route()
        .route_table_id(route_table_id)
        .destination_cidr_block(destination_cidr)
        .vpc_peering_connection_id(peer_id)
        .send()
        .await?;
    Ok(())
}

/// Finds VPC peering connections by deployer tag
pub async fn find_vpc_peering_by_tag(
    client: &Ec2Client,
    tag: &str,
) -> Result<Vec<String>, Ec2Error> {
    let resp = client
        .describe_vpc_peering_connections()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .vpc_peering_connections
        .unwrap_or_default()
        .into_iter()
        .map(|p| p.vpc_peering_connection_id.unwrap())
        .collect())
}

/// Deletes a VPC peering connection
pub async fn delete_vpc_peering(client: &Ec2Client, peering_id: &str) -> Result<(), Ec2Error> {
    client
        .delete_vpc_peering_connection()
        .vpc_peering_connection_id(peering_id)
        .send()
        .await?;
    Ok(())
}

/// Waits for a VPC peering connection to be deleted
pub async fn wait_for_vpc_peering_deletion(
    ec2_client: &Ec2Client,
    peer_id: &str,
) -> Result<(), Ec2Error> {
    loop {
        let resp = ec2_client
            .describe_vpc_peering_connections()
            .vpc_peering_connection_ids(peer_id)
            .send()
            .await?;
        if let Some(connections) = resp.vpc_peering_connections {
            if let Some(connection) = connections.first() {
                if connection.status.as_ref().unwrap().code
                    == Some(VpcPeeringConnectionStateReasonCode::Deleted)
                {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        } else {
            return Ok(());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

/// Finds instances by deployer tag
pub async fn find_instances_by_tag(
    ec2_client: &Ec2Client,
    tag: &str,
) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client
        .describe_instances()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .reservations
        .unwrap_or_default()
        .into_iter()
        .flat_map(|r| r.instances.unwrap_or_default())
        .map(|i| i.instance_id.unwrap())
        .collect())
}

/// Terminates specified instances
pub async fn terminate_instances(
    ec2_client: &Ec2Client,
    instance_ids: &[String],
) -> Result<(), Ec2Error> {
    if instance_ids.is_empty() {
        return Ok(());
    }
    ec2_client
        .terminate_instances()
        .set_instance_ids(Some(instance_ids.to_vec()))
        .send()
        .await?;
    Ok(())
}

/// Waits for instances to be terminated
pub async fn wait_for_instances_terminated(
    ec2_client: &Ec2Client,
    instance_ids: &[String],
) -> Result<(), Ec2Error> {
    loop {
        let resp = ec2_client
            .describe_instances()
            .set_instance_ids(Some(instance_ids.to_vec()))
            .send()
            .await?;
        let instances = resp
            .reservations
            .unwrap_or_default()
            .into_iter()
            .flat_map(|r| r.instances.unwrap_or_default())
            .collect::<Vec<_>>();
        if instances.iter().all(|i| {
            i.state.as_ref().unwrap().name.as_ref().unwrap() == &InstanceStateName::Terminated
        }) {
            return Ok(());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

/// Finds security groups by deployer tag
pub async fn find_security_groups_by_tag(
    ec2_client: &Ec2Client,
    tag: &str,
) -> Result<Vec<SecurityGroup>, Ec2Error> {
    let resp = ec2_client
        .describe_security_groups()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .security_groups
        .unwrap_or_default()
        .into_iter()
        .collect())
}

/// Deletes a security group
pub async fn delete_security_group(ec2_client: &Ec2Client, sg_id: &str) -> Result<(), Ec2Error> {
    ec2_client
        .delete_security_group()
        .group_id(sg_id)
        .send()
        .await?;
    Ok(())
}

/// Finds route tables by deployer tag
pub async fn find_route_tables_by_tag(
    ec2_client: &Ec2Client,
    tag: &str,
) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client
        .describe_route_tables()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .route_tables
        .unwrap_or_default()
        .into_iter()
        .map(|rt| rt.route_table_id.unwrap())
        .collect())
}

/// Deletes a route table
pub async fn delete_route_table(ec2_client: &Ec2Client, rt_id: &str) -> Result<(), Ec2Error> {
    ec2_client
        .delete_route_table()
        .route_table_id(rt_id)
        .send()
        .await?;
    Ok(())
}

/// Finds Internet Gateways by deployer tag
pub async fn find_igws_by_tag(ec2_client: &Ec2Client, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client
        .describe_internet_gateways()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .internet_gateways
        .unwrap_or_default()
        .into_iter()
        .map(|igw| igw.internet_gateway_id.unwrap())
        .collect())
}

/// Finds the VPC ID attached to an Internet Gateway
pub async fn find_vpc_by_igw(ec2_client: &Ec2Client, igw_id: &str) -> Result<String, Ec2Error> {
    let resp = ec2_client
        .describe_internet_gateways()
        .internet_gateway_ids(igw_id)
        .send()
        .await?;
    Ok(resp.internet_gateways.unwrap()[0]
        .attachments
        .as_ref()
        .unwrap()[0]
        .vpc_id
        .as_ref()
        .unwrap()
        .clone())
}

/// Detaches an Internet Gateway from a VPC
pub async fn detach_igw(
    ec2_client: &Ec2Client,
    igw_id: &str,
    vpc_id: &str,
) -> Result<(), Ec2Error> {
    ec2_client
        .detach_internet_gateway()
        .internet_gateway_id(igw_id)
        .vpc_id(vpc_id)
        .send()
        .await?;
    Ok(())
}

/// Deletes an Internet Gateway
pub async fn delete_igw(ec2_client: &Ec2Client, igw_id: &str) -> Result<(), Ec2Error> {
    ec2_client
        .delete_internet_gateway()
        .internet_gateway_id(igw_id)
        .send()
        .await?;
    Ok(())
}

/// Finds subnets by deployer tag
pub async fn find_subnets_by_tag(
    ec2_client: &Ec2Client,
    tag: &str,
) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client
        .describe_subnets()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .subnets
        .unwrap_or_default()
        .into_iter()
        .map(|subnet| subnet.subnet_id.unwrap())
        .collect())
}

/// Deletes a subnet
pub async fn delete_subnet(ec2_client: &Ec2Client, subnet_id: &str) -> Result<(), Ec2Error> {
    ec2_client
        .delete_subnet()
        .subnet_id(subnet_id)
        .send()
        .await?;
    Ok(())
}

/// Finds VPCs by deployer tag
pub async fn find_vpcs_by_tag(ec2_client: &Ec2Client, tag: &str) -> Result<Vec<String>, Ec2Error> {
    let resp = ec2_client
        .describe_vpcs()
        .filters(Filter::builder().name("tag:deployer").values(tag).build())
        .send()
        .await?;
    Ok(resp
        .vpcs
        .unwrap_or_default()
        .into_iter()
        .map(|vpc| vpc.vpc_id.unwrap())
        .collect())
}

/// Deletes a VPC
pub async fn delete_vpc(ec2_client: &Ec2Client, vpc_id: &str) -> Result<(), Ec2Error> {
    ec2_client.delete_vpc().vpc_id(vpc_id).send().await?;
    Ok(())
}

/// Enforces that all instance types are ARM64-based
pub async fn assert_arm64_support(
    client: &Ec2Client,
    instance_types: &[String],
) -> Result<(), Ec2Error> {
    let mut next_token: Option<String> = None;
    let mut supported_instance_types = HashSet::new();

    // Loop through all pages of results
    loop {
        // Get the next page of instance types
        let mut request = client.describe_instance_types().filters(
            Filter::builder()
                .name("processor-info.supported-architecture")
                .values("arm64")
                .build(),
        );
        if let Some(token) = next_token {
            request = request.next_token(token);
        }
        let response = request.send().await?;

        // Collect instance types from this page
        for instance_type in response.instance_types.unwrap_or_default() {
            if let Some(it) = instance_type.instance_type {
                supported_instance_types.insert(it.to_string());
            }
        }

        // Check if there’s another page
        next_token = response.next_token;
        if next_token.is_none() {
            break;
        }
    }

    // Validate all requested instance types
    for instance_type in instance_types {
        if !supported_instance_types.contains(instance_type) {
            return Err(Ec2Error::from(BuildError::other(format!(
                "instance type {} not ARM64-based",
                instance_type
            ))));
        }
    }
    Ok(())
}

/// Finds the availability zone that supports all required instance types
pub async fn find_availability_zone(
    client: &Ec2Client,
    instance_types: &[String],
) -> Result<String, Ec2Error> {
    // Retrieve all instance type offerings for availability zones in the region
    let offerings = client
        .describe_instance_type_offerings()
        .location_type("availability-zone".into())
        .filters(
            Filter::builder()
                .name("instance-type")
                .set_values(Some(instance_types.to_vec()))
                .build(),
        )
        .send()
        .await?
        .instance_type_offerings
        .unwrap_or_default();

    // Build a map from availability zone to the set of supported instance types
    let mut az_to_instance_types: HashMap<String, HashSet<String>> = HashMap::new();
    for offering in offerings {
        if let (Some(location), Some(instance_type)) = (
            offering.location,
            offering.instance_type.map(|it| it.to_string()), // Convert enum to String if necessary
        ) {
            az_to_instance_types
                .entry(location)
                .or_default()
                .insert(instance_type);
        }
    }

    // Convert the required instance types to a HashSet for efficient subset checking
    let required_instance_types: HashSet<String> = instance_types.iter().cloned().collect();

    // Find an availability zone that supports all required instance types
    for (az, supported_types) in az_to_instance_types {
        if required_instance_types.is_subset(&supported_types) {
            return Ok(az); // Return the first matching availability zone
        }
    }

    // If no availability zone supports all instance types, return an error
    Err(Ec2Error::from(BuildError::other(format!(
        "no availability zone supports all required instance types: {:?}",
        instance_types
    ))))
}

/// Waits until all network interfaces associated with a security group are deleted
pub async fn wait_for_enis_deleted(ec2_client: &Ec2Client, sg_id: &str) -> Result<(), Ec2Error> {
    loop {
        let resp = ec2_client
            .describe_network_interfaces()
            .filters(Filter::builder().name("group-id").values(sg_id).build())
            .send()
            .await?;
        if resp.network_interfaces.unwrap_or_default().is_empty() {
            return Ok(());
        }
        sleep(RETRY_INTERVAL).await;
    }
}
