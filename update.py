import urllib.parse
import json
import os
import json
import boto3
from botocore.utils import ensure_boolean
client = boto3.client('iam')
ec2_nVirginia = boto3.resource('ec2', region_name = 'us-east-1')
ec2_saoPaulo = boto3.resource('ec2', region_name = 'sa-east-1')

securityGroups = [
	{
		'description' : 'Test Home Office N. Virginia',
		'region' : 'us-east-1',
		'awsResource' : ec2_nVirginia.SecurityGroup(os.environ['TEST_HOME_OFFICE_NV']),
		'alias' : 'FHONV'
	},
	{
		'description' : 'Test Home Office Sao Paulo',
		'region' : 'sa-east-1',
		'awsResource' : ec2_saoPaulo.SecurityGroup(os.environ['TEST_HOME_OFFICE_SP']),
		'alias' : 'FHOSP'
	},
	#{
	#	'description' : 'DeveloperAccess Sao Paulo',
	#	'region' : 'sa-east-1',
	#	'awsResource' : ec2_saoPaulo.SecurityGroup('sg-05425757638087d9f'),
	#	'alias' : 'DASP'
	#}
]

def handler(event, context):
	tomdata = urllib.parse.parse_qs(event['body'])
	tomdatajson = json.loads(json.dumps(tomdata))

	userData = {
		'userName' : tomdatajson['username'][0],
		'requestAccessKey' : tomdatajson['accessKey'][0],
		'IP' : event['requestContext']['http']['sourceIp'],
		'activeAccessKeys' : [],
		'securityGroupsUpdated' : []
	}

	def updateRules(userData, securityGroup):
		print ('Checking ', securityGroup['description'])
		securityGroup = securityGroup['awsResource']
		securityGroup.reload()
		permissionsList = securityGroup.ip_permissions
		rulesUpdated = []
		portsAlreadyAlloed = []
		for permission in permissionsList:
			for IpRange in permission['IpRanges']:
				if userData['userName'] == IpRange['Description'] and permission['FromPort'] not in ipAlreadyAllowedFromPorts:
					revokeIngress = securityGroup.revoke_ingress(
						CidrIp = IpRange['CidrIp'],
						FromPort = permission['FromPort'],
						ToPort = permission['FromPort'],
						GroupId = securityGroup.group_id,
						IpProtocol = 'tcp',
						DryRun = False
					)
					addIngress = securityGroup.authorize_ingress(
						GroupId = securityGroup.group_id,
						IpPermissions = [
							{
								'FromPort': permission['FromPort'],
								'ToPort': permission['FromPort'],
								'IpProtocol': 'tcp',
								'IpRanges': [
									{
										'CidrIp': userData['IP'] + '/32',
										'Description': IpRange['Description']
									},
								]
							}
						]
					)
					rulesUpdated.append(permission['FromPort'])
				elif userData['userName'] == IpRange['Description'] and permission['FromPort'] in ipAlreadyAllowedFromPorts:
					print ('IP already allowed from port: ', permission['FromPort'])
					portsAlreadyAlloed.append(permission['FromPort'])
					pass
				else:
					pass

		print ('Updated rules for ports: ', rulesUpdated)
		if len(rulesUpdated) == 0 and len(portsAlreadyAlloed) == 0:
			print (userData['userName'], ' not found in any rule description')
			return False
		else:
			return True

	def validateInIAM(userData):
		try:
			responseIAM = client.list_access_keys(UserName = userData['userName'])
			for accessKey in responseIAM['AccessKeyMetadata']:
				if accessKey['Status'] == 'Active':
					userData['activeAccessKeys'].append(accessKey['AccessKeyId'])
				else:
					pass
			print ('User validated on IAM: OK')
			if userData['requestAccessKey'] in userData['activeAccessKeys']:
				print ('AccessKey: OK')
				return 'OK'
			else:
				print ('No valid AccessKey')
				return 'invalidAccessKey'
		except client.exceptions.NoSuchEntityException:
			print ('User not found on IAM')
			return 'iamUserNotFound'

	def update(userData, securityGroup):
		if validatedUser == 'OK':
			searchIP(userData['IP'],securityGroup['awsResource'])
			updateRulesStatus = updateRules(userData, securityGroup)
			if updateRulesStatus == True:
				userData['securityGroupsUpdated'].append(securityGroup['description'])
				return 0
			else:
				return 3
		elif validatedUser == 'invalidAccessKey':
				return 2
		else:
				return 1

	def searchIP(IP,securityGroup):
		permissionsList = securityGroup.ip_permissions
		cidrip = IP + '/32'
		for permission in permissionsList:
			for IpRange in permission['IpRanges']:
				if cidrip == IpRange['CidrIp']:
					ipAlreadyAllowedFromPorts.append(permission['FromPort'])

	ipAlreadyAllowedFromPorts = []
	response = {}
	validatedUser = validateInIAM(userData)
	for securityGroup in securityGroups:
		response.update({securityGroup['alias'] : update(userData, securityGroup)})

	allUserData = '''
		--------------------
		userName: {}
		requestAccessKey: {}
		IP: {}
		activeIAMAccessKey: {}
		securityGroupsUpdated: {}
		--------------------
		'''
	print (allUserData.format(
		userData['userName'],
		userData['requestAccessKey'],
		userData['IP'],
		userData['activeAccessKeys'],
		userData['securityGroupsUpdated']
	))

	return json.dumps(response, indent = 4)

# Status codes
# 0 = Success
# 1 = error: IAM user not found
# 2 = error: Invalid IAM AccessKey
# 3 = error: User not found in the Security Group

