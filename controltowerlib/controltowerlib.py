#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: controltowerlib.py
#
# Copyright 2020 Costas Tyfoxylos
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
#  of this software and associated documentation files (the "Software"), to
#  deal in the Software without restriction, including without limitation the
#  rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
#  sell copies of the Software, and to permit persons to whom the Software is
#  furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
#  all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
#  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
#  DEALINGS IN THE SOFTWARE.
#  pylint: disable=too-many-lines

"""
Main code for controltowerlib.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import copy
import json
import logging
import time
from functools import lru_cache, wraps
from time import sleep

import boto3
import botocore
from awsauthenticationlib import AwsAuthenticator
from opnieuw import retry

from .controltowerlibexceptions import (UnsupportedTarget,
                                        OUCreating,
                                        NoServiceCatalogAccess,
                                        NonExistentSCP,
                                        NoSuspendedOU,
                                        ServiceCallFailed,
                                        ControlTowerBusy,
                                        ControlTowerNotDeployed,
                                        PreDeployValidationFailed)

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''18-02-2020'''
__copyright__ = '''Copyright 2020, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''MIT'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

# This is the main prefix used for logging
LOGGER_BASENAME = '''controltowerlib'''
LOGGER = logging.getLogger(LOGGER_BASENAME)
LOGGER.addHandler(logging.NullHandler())


CREATING_ACCOUNT_ERROR_MESSAGE = 'Package is in state CREATING, but must be in state AVAILABLE'


class LoggerMixin:  # pylint: disable=too-few-public-methods
    """Logger."""

    @property
    def logger(self):
        """Exposes the logger to be used by objects using the Mixin.

        Returns:
            logger (logger): The properly named logger.

        """
        return logging.getLogger(f'{LOGGER_BASENAME}.{self.__class__.__name__}')


class AccountFactory:  # pylint: disable=too-few-public-methods, too-many-instance-attributes
    """Models the account factory data of service catalog."""

    def __init__(self, service_catalog_client, data):
        self._service_catalog = service_catalog_client
        self._data = data
        self.has_default_path = self._data.get('HasDefaultPath')
        self.id = self._data.get('Id')  # pylint: disable=invalid-name
        self.name = self._data.get('Name')
        self.owner = self._data.get('Owner')
        self.product_id = self._data.get('ProductId')
        self.short_description = self._data.get('ShortDescription')
        self.type = self._data.get('Type')


class ServiceControlPolicy:
    """Models the account factory data of service catalog."""

    def __init__(self, data):
        self._data = data

    @property
    def arn(self):
        """Arn."""
        return self._data.get('Arn')

    @property
    def aws_managed(self):
        """Aws Managed."""
        return self._data.get('AwsManaged')

    @property
    def description(self):
        """Description."""
        return self._data.get('Description')

    @property
    def id(self):  # pylint: disable=invalid-name
        """Id."""
        return self._data.get('Id')

    @property
    def name(self):
        """Name."""
        return self._data.get('Name')

    @property
    def type(self):
        """Type."""
        return self._data.get('Type')


class GuardRail(LoggerMixin):
    """Models the guard rail data."""

    def __init__(self, control_tower, data):
        self.control_tower = control_tower
        self._data_ = data

    @property
    def _data(self):
        """The data of the guard rail as returned by the api."""
        return self._data_

    @property
    def behavior(self):
        """Behavior."""
        return self._data_.get('Behavior')

    @property
    def category(self):
        """Category."""
        return self._data_.get('Category')

    @property
    def description(self):
        """Description."""
        return self._data_.get('Description')

    @property
    def display_name(self):
        """DisplayName."""
        return self._data_.get('DisplayName')

    @property
    def name(self):
        """Name."""
        return self._data_.get('Name')

    @property
    def provider(self):
        """Provider."""
        return self._data_.get('Provider')

    @property
    def regional_preference(self):
        """Regional preference."""
        return self._data_.get('RegionalPreference')

    @property
    def type(self):
        """Type."""
        return self._data_.get('Type')

    @property
    def compliancy_status(self):
        """Compliancy status."""
        payload = self.control_tower._get_api_payload(content_string={'GuardrailName': self.name},  # pylint: disable=protected-access
                                                      target='getGuardrailComplianceStatus')
        self.logger.debug('Trying to get the compliancy status with payload "%s"', payload)
        response = self.control_tower.session.post(self.control_tower.url, json=payload)
        if not response.ok:
            self.logger.error('Failed to get the drift message of the landing zone with response status "%s" and '
                              'response text "%s"',
                              response.status_code, response.text)
            return None
        return response.json().get('ComplianceStatus')


class CoreAccount:
    """Models the core landing zone account data."""

    def __init__(self, control_tower, account_label, data):
        self.control_tower = control_tower
        self._label = account_label
        self._data_ = data

    @property
    def _data(self):
        """The data of the account as returned by the api."""
        return self._data_

    @property
    def label(self):
        """Account label."""
        return self._label

    @property
    def email(self):
        """Email."""
        return self._data_.get('AccountEmail')

    @property
    def id(self):  # pylint: disable=invalid-name
        """Id."""
        return self._data_.get('AccountId')

    @property
    def core_resource_mappings(self):
        """Core resource mappings."""
        return self._data_.get('CoreResourceMappings')

    @property
    def stack_set_arn(self):
        """Stack set arn."""
        return self._data_.get('StackSetARN')


class ControlTowerAccount(LoggerMixin):  # pylint: disable=too-many-public-methods
    """Models the account data."""

    def __init__(self, control_tower, data, info_polling_interval=30):
        self.control_tower = control_tower
        self.service_catalog = control_tower.service_catalog
        self.organizations = control_tower.organizations
        self._data_ = data
        self._service_catalog_data_ = None
        self._record_data_ = None
        self._info_polling_interval = info_polling_interval

    @property
    def _data(self):
        """The data of the account as returned by the api."""
        return self._data_

    @property
    def _service_catalog_data(self):
        if self._service_catalog_data_ is None:
            data = self.service_catalog.search_provisioned_products(Filters={'SearchQuery': [f'physicalId:{self.id}']})
            if not data.get('TotalResultsCount'):
                self._service_catalog_data_ = {}
            else:
                self._service_catalog_data_ = data.get('ProvisionedProducts', [{}]).pop()
        return self._service_catalog_data_

    @property
    def _record_data(self):
        if self._record_data_ is None:
            if not self.last_record_id:
                self._record_data_ = {}
            else:
                self._record_data_ = self.service_catalog.describe_record(Id=self.last_record_id)
        return self._record_data_

    @property
    def email(self):
        """Email."""
        return self._data_.get('AccountEmail')

    @property
    def id(self):  # pylint: disable=invalid-name
        """Id."""
        return self._data_.get('AccountId')

    @property
    def name(self):
        """Name."""
        return self._data_.get('AccountName')

    @property
    def arn(self):
        """Arn."""
        return self._data_.get('Arn')

    @property
    def owner(self):
        """Owner."""
        return self._data_.get('Owner')

    @property
    def provision_state(self):
        """Provision state."""
        return self._data_.get('ProvisionState')

    @property
    def status(self):
        """Status."""
        return self._data_.get('Status')

    @property
    def landing_zone_version(self):
        """Landing zone version."""
        return self._data_.get('DeployedLandingZoneVersion')

    @property
    def has_available_update(self):
        """If the account is behind the landing zone version."""
        return float(self.landing_zone_version) < float(self.control_tower.landing_zone_version)

    @property
    def guardrail_compliance_status(self):
        """Retrieves the guardrail compliancy status for the account.

        Returns:
            status (str): COMPLIANT|NON COMPLIANT

        """
        payload = self.control_tower._get_api_payload(content_string={'AccountId': self.id},  # pylint: disable=protected-access
                                                      target='getGuardrailComplianceStatus')
        response = self.control_tower.session.post(self.control_tower.url, json=payload)
        if not response.ok:
            self.logger.error('Failed to get compliancy status from api.')
            return False
        return response.json().get('ComplianceStatus')

    @property
    def organizational_unit(self):
        """Organizational Unit."""
        return self.control_tower.get_organizational_unit_by_id(self._data_.get('ParentOrganizationalUnitId'))

    @property
    def stack_arn(self):
        """Stack Arn."""
        return self._service_catalog_data.get('Arn')

    @property
    def created_time(self):
        """Created Time."""
        return self._service_catalog_data.get('CreatedTime')

    @property
    def service_catalog_id(self):
        """Service Catalog ID."""
        return self._service_catalog_data.get('Id')

    @property
    def idempotency_token(self):
        """Idempotency Token."""
        return self._service_catalog_data.get('IdempotencyToken')

    @property
    def last_record_id(self):
        """Last Record ID."""
        return self._service_catalog_data.get('LastRecordId')

    @property
    def physical_id(self):
        """Physical ID."""
        return self._service_catalog_data.get('PhysicalId')

    @property
    def service_catalog_product_id(self):
        """Service catalog product ID."""
        return self._service_catalog_data.get('ProductId')

    @property
    def provisioning_artifact_id(self):
        """Provisioning artifact ID."""
        return self._service_catalog_data.get('ProvisioningArtifactId')

    @property
    def service_catalog_tags(self):
        """Service catalog tags."""
        return self._service_catalog_data.get('Tags')

    @property
    def service_catalog_type(self):
        """Service catalog type."""
        return self._service_catalog_data.get('Type')

    @property
    def service_catalog_status(self):
        """Service catalog status."""
        return self._service_catalog_data.get('Status')

    @property
    def service_catalog_user_arn(self):
        """Service catalog user arn."""
        return self._service_catalog_data.get('UserArn')

    @property
    def user_arn_session(self):
        """User arn session."""
        return self._service_catalog_data.get('UserArnSession')

    def _refresh(self):
        self._data_ = self.control_tower.get_account_by_id(self.id)._data  # pylint: disable=protected-access
        self._record_data_ = None
        self._service_catalog_data_ = None

    def _get_record_entry(self, output_key):
        return next((entry for entry in self._record_data.get('RecordOutputs', [])
                     if entry.get('OutputKey', '') == output_key), {})

    @property
    def sso_user_email(self):
        """SSO user email."""
        return self._get_record_entry(output_key='SSOUserEmail').get('OutputValue')

    @property
    def sso_user_portal(self):
        """SSO user portal."""
        return self._get_record_entry(output_key='SSOUserPortal').get('OutputValue')

    def detach_service_control_policy(self, name):
        """Detaches a Service Control Policy from the account.

        Args:
            name (str): The name of the SCP to detach

        Returns:
            result (bool): True on success, False otherwise.

        """
        return self._action_service_control_policy('detach', name)

    def attach_service_control_policy(self, name):
        """Attaches a Service Control Policy to the account.

        Args:
            name (str): The name of the SCP to attach

        Returns:
            result (bool): True on success, False otherwise.

        """
        return self._action_service_control_policy('attach', name)

    def _action_service_control_policy(self, action, scp_name):
        scp = self.control_tower.get_service_control_policy_by_name(scp_name)
        if not scp:
            raise NonExistentSCP(scp_name)
        response = getattr(self.organizations, f'{action}_policy')(PolicyId=scp.id, TargetId=self.id)
        if not response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200:
            self.logger.error('Failed to %s SCP "%s" to account with response "%s"', action, scp.name, response)
            return False
        self.logger.debug('Successfully %sed SCP "%s" to account', action, scp.name)
        return True

    def _terminate(self):
        """Terminates an account that is in error.

        Returns:
            response (dict): The response from the api of the termination request.

        """
        return self.service_catalog.terminate_provisioned_product(ProvisionedProductId=self.service_catalog_id)

    def delete(self):
        """Delete."""
        suspended_ou = self.control_tower.get_organizational_unit_by_name(self.control_tower.suspended_ou_name)
        if not suspended_ou:
            raise NoSuspendedOU(self.control_tower.suspended_ou_name)
        self._terminate()
        while self.control_tower.busy:
            self.logger.debug('Waiting for control tower to terminate the account...')
            sleep(self._info_polling_interval)
        self.organizations.move_account(AccountId=self.id,
                                        SourceParentId=self.control_tower.root_ou.id,
                                        DestinationParentId=suspended_ou.id)
        self.attach_service_control_policy(self.control_tower.suspended_ou_name)
        self.detach_service_control_policy('FullAWSAccess')

    def update(self):
        """Updates the account in service catalog.

        Returns:
            True if the call succeeded False otherwise

        """
        if not self.has_available_update:
            return True
        if self.control_tower.busy:
            raise ControlTowerBusy
        arguments = {'ProductId': self.control_tower._account_factory.product_id,  # pylint: disable=protected-access
                     'ProvisionedProductName': self.name,
                     'ProvisioningArtifactId': self.control_tower._active_artifact.get('Id'),  # pylint: disable=protected-access
                     'ProvisioningParameters': [{'Key': 'AccountName',
                                                 'Value': self.name,
                                                 'UsePreviousValue': True},
                                                {'Key': 'AccountEmail',
                                                 'Value': self.email,
                                                 'UsePreviousValue': True},
                                                {'Key': 'SSOUserFirstName',
                                                 'Value': 'Control',
                                                 'UsePreviousValue': True},
                                                {'Key': 'SSOUserLastName',
                                                 'Value': 'Tower',
                                                 'UsePreviousValue': True},
                                                {'Key': 'SSOUserEmail',
                                                 'Value': self.email,
                                                 'UsePreviousValue': True},
                                                {'Key': 'ManagedOrganizationalUnit',
                                                 'Value': self.organizational_unit.name,
                                                 'UsePreviousValue': True}]}
        response = self.service_catalog.update_provisioned_product(**arguments)
        return response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200


class OrganizationsOU:
    """Model the data of an Organizations managed OU."""

    def __init__(self, data):
        self._data = data

    @property
    def id(self):  # pylint: disable=invalid-name
        """The id of the OU."""
        return self._data.get('Id')

    @property
    def name(self):
        """The name of the OU."""
        return self._data.get('Name')

    @property
    def arn(self):
        """The arn of the OU."""
        return self._data.get('Arn')


class ControlTowerOU:
    """Model the data of a Control Tower managed OU."""

    def __init__(self, control_tower, data):
        self.control_tower = control_tower
        self._data = data

    @property
    def create_date(self):
        """The date the ou was created in timestamp."""
        return self._data.get('CreateDate')

    @property
    def id(self):  # pylint: disable=invalid-name
        """OU ID."""
        return self._data.get('OrganizationalUnitId')

    @property
    def name(self):
        """The name of the OU."""
        return self._data.get('OrganizationalUnitName')

    @property
    def type(self):
        """The type of the OU."""
        return self._data.get('OrganizationalUnitType')

    @property
    def parent_ou_id(self):
        """The id of the parent OU."""
        return self._data.get('ParentOrganizationalUnitId')

    @property
    def parent_ou_name(self):
        """The name of the parent OU."""
        return self._data.get('ParentOrganizationalUnitName')

    def delete(self):
        """Deletes the ou.

        Returns:
            response (bool): True on success, False otherwise.

        """
        return self.control_tower.delete_organizational_unit(self.name)


class ControlTower(LoggerMixin):  # pylint: disable=too-many-instance-attributes,too-many-public-methods
    """Models Control Tower by wrapping around service catalog."""

    api_content_type = 'application/x-amz-json-1.1'
    api_user_agent = 'aws-sdk-js/2.528.0 promise'
    supported_targets = ['listManagedOrganizationalUnits',
                         'manageOrganizationalUnit',
                         'deregisterOrganizationalUnit',
                         'listManagedAccounts',
                         'getGuardrailComplianceStatus',
                         'describeManagedOrganizationalUnit',
                         'listGuardrailsForTarget',
                         'getAvailableUpdates',
                         'describeCoreService',
                         'getAccountInfo',
                         'listEnabledGuardrails',
                         'listGuardrails',
                         'listOrganizationalUnitsForParent',
                         'listDriftDetails',
                         'getLandingZoneStatus',
                         'setupLandingZone',
                         'getHomeRegion',
                         'listGuardrailViolations',
                         'getCatastrophicDrift',
                         'getGuardrailComplianceStatus',
                         'describeAccountFactoryConfig',
                         'performPreLaunchChecks'
                         ]
    core_account_types = ['PRIMARY', 'LOGGING', 'SECURITY']

    def validate_availability(method):  # pylint: disable=no-self-argument
        """Validation decorator."""
        @wraps(method)
        def wrap(*args, **kwargs):
            """Inner wrapper decorator."""
            logger = logging.getLogger(f'{LOGGER_BASENAME}.validation_decorator')
            contol_tower_instance = args[0]
            logger.debug('Decorating method: %s', method)
            if not contol_tower_instance.is_deployed:
                raise ControlTowerNotDeployed
            if contol_tower_instance.busy:
                raise ControlTowerBusy
            return method(*args, **kwargs)  # pylint: disable=not-callable
        return wrap

    def __init__(self, arn, settling_time=60, suspended_ou_name='Suspended'):
        self.aws_authenticator = AwsAuthenticator(arn)
        self.service_catalog = boto3.client('servicecatalog', **self.aws_authenticator.assumed_role_credentials)
        self.organizations = boto3.client('organizations', **self.aws_authenticator.assumed_role_credentials)
        self.session = self._get_authenticated_session()
        self._region = None
        self._is_deployed = None
        self.url = f'https://{self.region}.console.aws.amazon.com/controltower/api/controltower'
        self._account_factory = self._get_account_factory(self.service_catalog) if self.is_deployed else None
        self.settling_time = settling_time
        self.suspended_ou_name = suspended_ou_name
        self._root_ou = None
        self._update_data_ = None
        self._core_accounts = None

    @property
    def is_deployed(self):
        """The deployment status of control tower."""
        if not self._is_deployed:
            caller_region = self.aws_authenticator.region
            url = f'https://{caller_region}.console.aws.amazon.com/controltower/api/controltower'
            payload = self._get_api_payload(content_string={},
                                            target='getLandingZoneStatus',
                                            region=caller_region)
            self.logger.debug('Trying to get the deployed status of the landing zone with payload "%s"', payload)
            response = self.session.post(url, json=payload)
            if not response.ok:
                self.logger.error('Failed to get the deployed status of the landing zone with response status '
                                  '"%s" and response text "%s"',
                                  response.status_code, response.text)
                raise ServiceCallFailed(payload)
            self._is_deployed = response.json().get('LandingZoneStatus') != 'NOT_STARTED'
        return self._is_deployed

    @property
    def region(self):
        """Region."""
        if not self.is_deployed:
            self._region = self.aws_authenticator.region
            return self._region
        if self._region is None:
            caller_region = self.aws_authenticator.region
            url = f'https://{caller_region}.console.aws.amazon.com/controltower/api/controltower'
            payload = self._get_api_payload(content_string={}, target='getHomeRegion', region=caller_region)
            response = self.session.post(url, json=payload)
            if not response.ok:
                raise ServiceCallFailed(payload)
            self._region = response.json().get('HomeRegion')
        return self._region

    @property
    @validate_availability
    def core_accounts(self):
        """The core accounts of the landing zone.

        Returns:
            core_accounts (list): A list of the primary, logging and security account.

        """
        if self._core_accounts is None:
            core_accounts = []
            for account_type in self.core_account_types:
                payload = self._get_api_payload(content_string={'AccountType': account_type},
                                                target='describeCoreService')
                response = self.session.post(self.url, json=payload)
                if not response.ok:
                    raise ServiceCallFailed(f'Service call failed with payload {payload}')
                core_accounts.append(CoreAccount(self, account_type, response.json()))
            self._core_accounts = core_accounts
        return self._core_accounts

    @property
    @validate_availability
    def root_ou(self):
        """The root ou of control tower.

        Returns:
            root_ou (ControlTowerOU): The root ou object.

        """
        if self._root_ou is None:
            self._root_ou = self.get_organizational_unit_by_name('Root')
        return self._root_ou

    def _get_authenticated_session(self):
        return self.aws_authenticator.get_control_tower_authenticated_session()

    @property
    def _active_artifact(self):
        artifacts = self.service_catalog.list_provisioning_artifacts(ProductId=self._account_factory.product_id)
        return next((artifact for artifact in artifacts.get('ProvisioningArtifactDetails', [])
                     if artifact.get('Active')),
                    None)

    @staticmethod
    def _get_account_factory(service_catalog_client):
        filter_ = {'Owner': ['AWS Control Tower']}
        try:
            return AccountFactory(service_catalog_client,
                                  service_catalog_client.search_products(Filters=filter_
                                                                         ).get('ProductViewSummaries', [''])[0])
        except IndexError:
            raise NoServiceCatalogAccess(('Please make sure the role used has access to the "AWS Control Tower Account '
                                          'Factory Portfolio" in Service Catalog under "Groups, roles, and users"'))

    def _validate_target(self, target):
        if target not in self.supported_targets:
            raise UnsupportedTarget(target)
        return target

    def _get_api_payload(self,  # pylint: disable=too-many-arguments
                         content_string,
                         target,
                         method='POST',
                         params=None,
                         path=None,
                         region=None):
        target = self._validate_target(target)
        payload = {'contentString': json.dumps(content_string),
                   'headers': {'Content-Type': self.api_content_type,
                               'X-Amz-Target': f'AWSBlackbeardService.{target[0].capitalize() + target[1:]}',
                               'X-Amz-User-Agent': self.api_user_agent},
                   'method': method,
                   'operation': target,
                   'params': params or {},
                   'path': path or '/',
                   'region': region or self.region}
        return copy.deepcopy(payload)

    def _get_paginated_results(self,  # pylint: disable=too-many-arguments
                               content_payload,
                               target,
                               object_group=None,
                               object_type=None,
                               method='POST',
                               params=None,
                               path=None,
                               region=None,
                               next_token_marker='NextToken'):
        payload = self._get_api_payload(content_string=content_payload,
                                        target=target,
                                        method=method,
                                        params=params,
                                        path=f'/{path}/' if path else '/',
                                        region=region)
        response, next_token = self._get_partial_response(payload, next_token_marker)
        if not object_group:
            yield response.json()
        else:
            for data in response.json().get(object_group, []):
                if object_type:
                    yield object_type(self, data)
                else:
                    yield data
        while next_token:
            content_string = copy.deepcopy(json.loads(payload.get('contentString')))
            content_string.update({next_token_marker: next_token})
            payload.update({'contentString': json.dumps(content_string)})
            response, next_token = self._get_partial_response(payload, next_token_marker)
            if not object_group:
                yield response.json()
            else:
                for data in response.json().get(object_group, []):
                    if object_type:
                        yield object_type(self, data)
                    else:
                        yield data

    def _get_partial_response(self, payload, next_token_marker):
        response = self.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.debug('Failed getting partial response with payload :%s\n', payload)
            self.logger.debug('Response received :%s\n', response.content)
            raise ValueError(response.text)
        next_token = response.json().get(next_token_marker)
        return response, next_token

    @property
    def _update_data(self):
        if self._update_data_ is None:
            self._update_data_ = next(self._get_paginated_results(content_payload={},
                                                                  target='getAvailableUpdates'))
        return self._update_data_

    @property
    @validate_availability
    def baseline_update_available(self):
        """Baseline update available."""
        return self._update_data.get('BaselineUpdateAvailable')

    @property
    @validate_availability
    def guardrail_update_available(self):
        """Guardrail update available."""
        return self._update_data.get('GuardrailUpdateAvailable')

    @property
    @validate_availability
    def landing_zone_update_available(self):
        """Landing Zone update available."""
        return self._update_data.get('LandingZoneUpdateAvailable')

    @property
    @validate_availability
    def service_landing_zone_version(self):
        """Service landing zone version."""
        return self._update_data.get('ServiceLandingZoneVersion')

    @property
    @validate_availability
    def user_landing_zone_version(self):
        """User landing zone version."""
        return self._update_data.get('UserLandingZoneVersion')

    @property
    @validate_availability
    def landing_zone_version(self):
        """Landing zone version."""
        return self._update_data.get('UserLandingZoneVersion')

    @property
    @validate_availability
    def organizational_units(self):
        """The organizational units under control tower.

        Returns:
            organizational_units (OrganizationalUnit): A list of organizational units objects under control tower's
            control.

        """
        return self._get_paginated_results(content_payload={'MaxResults': 20},
                                           target='listManagedOrganizationalUnits',
                                           object_type=ControlTowerOU,
                                           object_group='ManagedOrganizationalUnitList',
                                           next_token_marker='NextToken')

    @validate_availability
    def register_organizations_ou(self, name):
        """Registers an Organizations OU under control tower.

        Args:
            name (str): The name of the Organizations OU to register to Control Tower.

        Returns:
            result (bool): True if successfull, False otherwise.

        """
        if self.get_organizational_unit_by_name(name):
            self.logger.info('OU "%s" is already registered with Control Tower.', name)
            return True
        org_ou = self.get_organizations_ou_by_name(name)
        if not org_ou:
            self.logger.error('OU "%s" does not exist under organizations.', name)
            return False
        return self._register_org_ou_in_control_tower(org_ou)

    @validate_availability
    def create_organizational_unit(self, name):
        """Creates a Control Tower managed organizational unit.

        Args:
            name (str): The name of the OU to create.

        Returns:
            result (bool): True if successfull, False otherwise.

        """
        self.logger.debug('Trying to create OU :"%s" under root ou', name)
        try:
            response = self.organizations.create_organizational_unit(ParentId=self.root_ou.id, Name=name)
        except botocore.exceptions.ClientError as err:
            status = err.response["ResponseMetadata"]["HTTPStatusCode"]
            error_code = err.response["Error"]["Code"]
            error_message = err.response["Error"]["Message"]
            if not status == 200:
                self.logger.error('Failed to create OU "%s" under Organizations with error code %s: %s',
                                  name, error_code, error_message)
                return False
        org_ou = OrganizationsOU(response.get('OrganizationalUnit', {}))
        self.logger.debug(response)
        return self._register_org_ou_in_control_tower(org_ou)

    def _register_org_ou_in_control_tower(self, org_ou):
        self.logger.debug('Trying to move management of OU under Control Tower')
        payload = self._get_api_payload(content_string={'OrganizationalUnitId': org_ou.id,
                                                        'OrganizationalUnitName': org_ou.name,
                                                        'ParentOrganizationalUnitId': self.root_ou.id,
                                                        'ParentOrganizationalUnitName': self.root_ou.name,
                                                        'OrganizationalUnitType': 'CUSTOM'},
                                        target='manageOrganizationalUnit')
        response = self.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error('Failed to register OU "%s" to Control Tower with response status "%s" '
                              'and response text "%s"',
                              org_ou.name, response.status_code, response.text)
            return False
        self.logger.debug('Giving %s time for the guardrails to be applied', self.settling_time)
        time.sleep(self.settling_time)
        self.logger.debug('Successfully moved management of OU "%s" under Control Tower', org_ou.name)
        return response.ok

    @validate_availability
    def delete_organizational_unit(self, name):
        """Deletes a Control Tower managed organizational unit.

        Args:
            name (str): The name of the OU to delete.

        Returns:
            result (bool): True if successfull, False otherwise.

        """
        organizational_unit = self.get_organizational_unit_by_name(name)
        if not organizational_unit:
            self.logger.error('No organizational unit with name :"%s" registered with Control Tower', name)
            return False
        payload = self._get_api_payload(content_string={'OrganizationalUnitId': organizational_unit.id},
                                        target='deregisterOrganizationalUnit')
        self.logger.debug('Trying to unregister OU "%s" with payload "%s"', name, payload)
        response = self.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error('Failed to unregister OU "%s" with response status "%s" and response text "%s"',
                              name, response.status_code, response.text)
            return False
        self.logger.debug('Successfully unregistered management of OU "%s" from Control Tower', name)
        self.logger.debug('Trying to delete OU "%s" from Organizations', name)
        response = self.organizations.delete_organizational_unit(OrganizationalUnitId=organizational_unit.id)
        self.logger.debug(response)
        return bool(response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200)

    @validate_availability
    def get_organizational_unit_by_name(self, name):
        """Gets a Control Tower managed Organizational Unit by name.

        Args:
            name (str): The name of the organizational unit to retrieve.

        Returns:
            result (ControlTowerOU): A OU object on success, None otherwise.

        """
        return next((ou for ou in self.organizational_units if ou.name == name), None)

    @validate_availability
    def get_organizational_unit_by_id(self, id_):
        """Gets a Control Tower managed Organizational Unit by id.

        Args:
            id_ (str): The id of the organizational unit to retrieve.

        Returns:
            result (ControlTowerOU): A OU object on success, None otherwise.

        """
        return next((ou for ou in self.organizational_units if ou.id == id_), None)

    @property
    @validate_availability
    def organizations_ous(self):
        """The organizational units under Organizations.

        Returns:
            organizational_units (OrganizationsOU): A list of organizational units objects under Organizations.

        """
        response = self.organizations.list_organizational_units_for_parent(ParentId=self.root_ou.id)
        return [OrganizationsOU(data)
                for data in response.get('OrganizationalUnits', [])]

    @validate_availability
    def get_organizations_ou_by_name(self, name):
        """Gets an Organizations managed Organizational Unit by name.

        Args:
            name (str): The name of the organizational unit to retrieve.

        Returns:
            result (OrganizationsOU): A OU object on success, None otherwise.

        """
        return next((ou for ou in self.organizations_ous if ou.name == name), None)

    @validate_availability
    def get_organizations_ou_by_id(self, id_):
        """Gets an Organizations managed Organizational Unit by id.

        Args:
            id_ (str): The id of the organizational unit to retrieve.

        Returns:
            result (OrganizationsOU): A OU object on success, None otherwise.

        """
        return next((ou for ou in self.organizations_ous if ou.id == id_), None)

    @validate_availability
    def get_organizations_ou_by_arn(self, arn):
        """Gets an Organizations managed Organizational Unit by arn.

        Args:
            arn (str): The arn of the organizational unit to retrieve.

        Returns:
            result (OrganizationsOU): A OU object on success, None otherwise.

        """
        return next((ou for ou in self.organizations_ous if ou.arn == arn), None)

    @property
    @validate_availability
    def accounts(self):
        """The accounts under control tower.

        Returns:
            accounts (Account): A list of account objects under control tower's control.

        """
        return self._get_paginated_results(content_payload={},
                                           target='listManagedAccounts',
                                           object_type=ControlTowerAccount,
                                           object_group='ManagedAccountList',
                                           next_token_marker='NextToken')

    @property
    def _service_catalog_accounts_data(self):
        products = self.service_catalog.search_provisioned_products()
        return [data for data in products.get('ProvisionedProducts', [])
                if data.get('Type', '') == 'CONTROL_TOWER_ACCOUNT']

    @validate_availability
    def get_available_accounts(self):
        """Retrieves the available accounts from control tower.

        Returns:
            accounts (Account): A list of available account objects under control tower's control.

        """
        return self._filter_for_status('AVAILABLE')

    @validate_availability
    def get_erroring_accounts(self):
        """Retrieves the erroring accounts from control tower.

        Returns:
            accounts (Account): A list of erroring account objects under control tower's control.

        """
        return self._filter_for_status('ERROR')

    @validate_availability
    def get_accounts_with_available_updates(self):
        """Retrieves the accounts that have available updates from control tower.

        Returns:
            accounts (Account): A list of account objects under control tower's control with available updates.

        """
        return [account for account in self.accounts if account.has_available_update]

    @validate_availability
    def get_updated_accounts(self):
        """Retrieves the accounts that have no available updates from control tower.

        Returns:
            accounts (Account): A list of account objects under control tower's control with no available updates.

        """
        return [account for account in self.accounts if not account.has_available_update]

    def get_changing_accounts(self):
        """Retrieves the under change accounts from control tower.

        Returns:
            accounts (Account): A list of under change account objects under control tower's control.

        """
        products = self.service_catalog.search_provisioned_products()

        return [ControlTowerAccount(self, {'AccountId': data.get('PhysicalId')})
                for data in products.get('ProvisionedProducts', [])
                if all([data.get('Type', '') == 'CONTROL_TOWER_ACCOUNT',
                        data.get('Status', '') == 'UNDER_CHANGE'])]

    def _filter_for_status(self, status):
        return [account for account in self.accounts if account.service_catalog_status == status]

    def _get_by_attribute(self, attribute, value):
        return next((account for account in self.accounts
                     if getattr(account, attribute) == value), None)

    def _get_service_catalog_data_by_account_id(self, account_id):
        return next((data for data in self._service_catalog_accounts_data
                     if data.get('PhysicalId') == account_id), None)

    @validate_availability
    def get_account_by_name(self, name):
        """Retrieves an account by name.

        Returns:
            account (Account): An account object that matches the name or None.

        """
        return self._get_by_attribute('name', name)

    @validate_availability
    def get_account_by_id(self, id_):
        """Retrieves an account by id.

        Returns:
            account (Account): An account object that matches the id or None.

        """
        return self._get_by_attribute('id', id_)

    @validate_availability
    def get_account_by_arn(self, arn):
        """Retrieves an account by arn.

        Returns:
            account (Account): An account object that matches the arn or None.

        """
        return self._get_by_attribute('arn', arn)

    @retry(retry_on_exceptions=OUCreating, max_calls_total=7, retry_window_after_first_call_in_seconds=60)
    @validate_availability
    def create_account(self,  # pylint: disable=too-many-arguments
                       account_name,
                       account_email,
                       organizational_unit,
                       product_name=None,
                       sso_first_name=None,
                       sso_last_name=None,
                       sso_user_email=None):
        """Creates a Control Tower managed account.

        Args:
            account_name (str): The name of the account.
            account_email (str): The email of the account.
            organizational_unit (str): The organizational unit that the account should be under.
            product_name (str): The product name, if nothing is provided it uses the account name.
            sso_first_name (str): The first name of the SSO user, defaults to "Control"
            sso_last_name (str): The last name of the SSO user, defaults to "Tower"
            sso_user_email (str): The email of the sso, if nothing is provided it uses the account email.

        Returns:
            result (bool): True on success, False otherwise.

        """
        product_name = product_name or account_name
        sso_user_email = sso_user_email or account_email
        sso_first_name = sso_first_name or 'Control'
        sso_last_name = sso_last_name or 'Tower'
        if not self.get_organizational_unit_by_name(organizational_unit):
            if not self.create_organizational_unit(organizational_unit):
                self.logger.error('Unable to create the organizational unit!')
                return False
        arguments = {'ProductId': self._account_factory.product_id,
                     'ProvisionedProductName': product_name,
                     'ProvisioningArtifactId': self._active_artifact.get('Id'),
                     'ProvisioningParameters': [{'Key': 'AccountName',
                                                 'Value': account_name},
                                                {'Key': 'AccountEmail',
                                                 'Value': account_email},
                                                {'Key': 'SSOUserFirstName',
                                                 'Value': sso_first_name},
                                                {'Key': 'SSOUserLastName',
                                                 'Value': sso_last_name},
                                                {'Key': 'SSOUserEmail',
                                                 'Value': sso_user_email},
                                                {'Key': 'ManagedOrganizationalUnit',
                                                 'Value': organizational_unit}]}
        try:
            response = self.service_catalog.provision_product(**arguments)
        except botocore.exceptions.ClientError as err:
            if CREATING_ACCOUNT_ERROR_MESSAGE in err.response['Error']['Message']:
                raise OUCreating
            raise
        return response.get('ResponseMetadata', {}).get('HTTPStatusCode') == 200

    @property
    @validate_availability
    def service_control_policies(self):
        """The service control policies under organization.

        Returns:
            service_control_policies (list): A list of SCPs under the organization.

        """
        return [ServiceControlPolicy(data)
                for data in self.organizations.list_policies(Filter='SERVICE_CONTROL_POLICY').get('Policies', [])]

    @validate_availability
    def get_service_control_policy_by_name(self, name):
        """Retrieves a service control policy by name.

        Args:
            name (str): The name of the SCP to retrieve

        Returns:
            scp (ServiceControlPolicy): The scp if a match is found else None.

        """
        return next((scp for scp in self.service_control_policies
                     if scp.name == name), None)

    @validate_availability
    def update(self):
        """Updates the control tower to the latest version.

        Returns:
            bool: True on success, False on failure.

        """
        if not self.landing_zone_update_available:
            self.logger.warning('Landing zone does not seem to need update, is at version %s',
                                self.landing_zone_version)
            return False
        log_account = next((account for account in self.core_accounts if account.label == 'LOGGING'), None)
        if not log_account:
            raise ServiceCallFailed('Could not retrieve logging account to get the email.')
        security_account = next((account for account in self.core_accounts if account.label == 'SECURITY'), None)
        if not security_account:
            raise ServiceCallFailed('Could not retrieve security account to get the email.')
        payload = self._get_api_payload(content_string={'HomeRegion': self.region,
                                                        'LogAccountEmail': log_account.email,
                                                        'SecurityAccountEmail': security_account.email},
                                        target='setupLandingZone')
        self.logger.debug('Trying to update the landing zone with payload "%s"', payload)
        response = self.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error('Failed to update the landing zone with response status "%s" and response text "%s"',
                              response.status_code, response.text)
            return False
        self.logger.debug('Successfully started updating landing zone')
        return True

    @property
    def busy(self):
        """Busy."""
        return any([self.status == 'IN_PROGRESS',
                    self.get_changing_accounts()])

    @property
    def status(self):
        """Status."""
        return self._get_status().get('LandingZoneStatus')

    @property
    def percentage_complete(self):
        """Percentage complete."""
        return self._get_status().get('PercentageComplete')

    @property
    def deploying_messages(self):
        """Deploying messages."""
        return self._get_status().get('Messages')

    @property
    def region_metadata_list(self):
        """Region metadata list."""
        return self._get_status().get('RegionMetadataList')

    @lru_cache(maxsize=2)
    def _get_status(self):
        payload = self._get_api_payload(content_string={},
                                        target='getLandingZoneStatus')
        self.logger.debug('Trying to get the landing zone status with payload "%s"', payload)
        response = self.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error('Failed to get the landing zone status with response status "%s" and response text "%s"',
                              response.status_code, response.text)
            return {}
        self.logger.debug('Successfully got landing zone status.')
        return response.json()

    @property
    @validate_availability
    def drift_messages(self):
        """Drift messages."""
        payload = self._get_api_payload(content_string={},
                                        target='listDriftDetails')
        self.logger.debug('Trying to get the drift messages of the landing zone with payload "%s"', payload)
        response = self.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error('Failed to get the drift message of the landing zone with response status "%s" and '
                              'response text "%s"',
                              response.status_code, response.text)
            return []
        return response.json().get('DriftDetails')

    @property
    @validate_availability
    def enabled_guard_rails(self):
        """Enabled guard rails."""
        output = []
        for result in self._get_paginated_results(content_payload={}, target='listEnabledGuardrails'):
            output.extend([GuardRail(self, data) for data in result.get('EnabledGuardrailList')])
        return output

    @property
    @validate_availability
    def guard_rails(self):
        """Guard rails."""
        output = []
        for result in self._get_paginated_results(content_payload={}, target='listGuardrails'):
            output.extend([GuardRail(self, data) for data in result.get('GuardrailList')])
        return output

    @property
    @validate_availability
    def guard_rails_violations(self):
        """List guard rails violations."""
        output = []
        for result in self._get_paginated_results(content_payload={}, target='listGuardrailViolations'):
            output.extend(result.get('GuardrailViolationList'))
        return output

    @property
    @validate_availability
    def catastrophic_drift(self):
        """List of catastrophic drift."""
        output = []
        for result in self._get_paginated_results(content_payload={}, target='getCatastrophicDrift'):
            output.extend(result.get('DriftDetails'))
        return output

    @property
    def _account_factory_config(self):
        """The config of the account factory."""
        payload = self._get_api_payload(content_string={},
                                        target='describeAccountFactoryConfig')
        self.logger.debug('Trying to get the account factory config of the landing zone with payload "%s"', payload)
        response = self.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error('Failed to get the the account factory config of the landing zone with response status '
                              '"%s" and response text "%s"',
                              response.status_code, response.text)
            return {}
        return response.json().get('AccountFactoryConfig')

    def _pre_deploy_check(self):
        """Pre deployment check."""
        payload = self._get_api_payload(content_string={},
                                        target='performPreLaunchChecks')
        self.logger.debug('Trying the pre deployment check with payload "%s"', payload)
        response = self.session.post(self.url, json=payload)
        if not response.ok:
            self.logger.error('Failed to do the pre deployment checks with response status '
                              '"%s" and response text "%s"',
                              response.status_code, response.text)
            return []
        return response.json().get('PreLaunchChecksResult')

    def deploy(self, logging_account_email, security_account_email):
        """Deploys control tower.

        Returns:
            bool: True on success, False on failure.

        """
        return NotImplemented
        # if self.is_deployed:
        #     self.logger.warning('Control tower does not seem to need deploying, already deployed.')
        #     return True
        # validation = self._pre_deploy_check()
        # if not all([list(entry.values()).pop().get('Result') == 'SUCCESS' for entry in validation]):
        #     raise PreDeployValidationFailed(validation)
        # validate that the emails are not used anywhere.
        # {"headers": {"X-Amz-User-Agent": "aws-sdk-js/2.528.0 promise", "Content-Type": "application/x-amz-json-1.1",
        #              "X-Amz-Target": "AWSBlackbeardService.GetAccountInfo"}, "path": "/", "method": "POST",
        #  "region": "eu-west-1", "params": {},
        #  "contentString": "{\"AccountEmail\":\"EMAILTOCHECK\"}",
        #  "operation": "getAccountInfo"}

        # {"HomeRegion": "eu-west-1", "LogAccountEmail": "logging-testing-account@domain.com",
        #  "SecurityAccountEmail": "security-testing-account@domain.com",
        #  "RegionConfigurationList": [{"Region": "us-east-1", "RegionConfigurationStatus": "DISABLED"},
        #                              {"Region": "us-east-2", "RegionConfigurationStatus": "DISABLED"},
        #                              {"Region": "us-west-2", "RegionConfigurationStatus": "DISABLED"},
        #                              {"Region": "eu-west-1", "RegionConfigurationStatus": "ENABLED"},
        #                              {"Region": "ap-southeast-2", "RegionConfigurationStatus": "DISABLED"},
        #                              {"Region": "ap-southeast-1", "RegionConfigurationStatus": "DISABLED"},
        #                              {"Region": "eu-central-1", "RegionConfigurationStatus": "DISABLED"},
        #                              {"Region": "eu-west-2", "RegionConfigurationStatus": "DISABLED"},
        #                              {"Region": "ca-central-1", "RegionConfigurationStatus": "DISABLED"},
        #                              {"Region": "eu-north-1", "RegionConfigurationStatus": "DISABLED"}
        #

        # payload = self._get_api_payload(content_string={'HomeRegion': self.region,
        #                                                 'LogAccountEmail': logging_account_email,
        #                                                 'SecurityAccountEmail': security_account_email},
        #                                 target='setupLandingZone')
        # self.logger.debug('Trying to deploy control tower with payload "%s"', payload)
        # headers = {'Referer':
        #                f'https://{self.region}.console.aws.amazon.com/controltower/home/setup?region={self.region}'}
        # response = self.session.post(self.url, headers=headers, json=payload)
        # if not response.ok:
        #     self.logger.error('Failed to deploy control tower with response status "%s" and response text "%s"',
        #                       response.status_code, response.text)
        #     return False
        # self.logger.debug('Successfully started deploying control tower.')
        # return True
