# Edit the config_and_params.json file and add the necessary parameter values.
# Ensure that the provided input_params yield the correct output schema.
# Add logic for validating conditional_output_schema or if schema is other than dict.
# Add any specific assertions in each test case, based on the expected response.

"""
Copyright start
MIT License
Copyright (c) 2024 Fortinet Inc
Copyright end
"""

import pytest
from testframework.conftest import valid_configuration, invalid_configuration, valid_configuration_with_token,\
    connector_id, connector_details, info_json, params_json
from testframework.helpers.test_helpers import run_health_check_success, run_invalid_config_test, run_success_test,\
    run_output_schema_validation, run_invalid_param_test, set_report_metadata
    

@pytest.mark.check_health
def test_check_health_success(valid_configuration, connector_details):
    set_report_metadata(connector_details, "Health Check", "Verify with valid Configuration")
    result = run_health_check_success(valid_configuration, connector_details)
    assert result.get('status') == 'Available'
    

@pytest.mark.check_health
def test_check_health_invalid_tenant_id(invalid_configuration, connector_id, connector_details, params_json):
    set_report_metadata(connector_details, "Health Check", "Verify with invalid Directory (tenant) ID")
    result = run_invalid_config_test(invalid_configuration, connector_id, connector_details, param_name='tenant_id',
                                     param_type='text', config=params_json['config'])
    assert result.get('status') == "Disconnected"
    

@pytest.mark.check_health
def test_check_health_invalid_subscription_id(invalid_configuration, connector_id, connector_details, params_json):
    set_report_metadata(connector_details, "Health Check", "Verify with invalid Subscription ID")
    result = run_invalid_config_test(invalid_configuration, connector_id, connector_details, param_name='subscription_id',
                                     param_type='text', config=params_json['config'])
    assert result.get('status') == "Disconnected"
    

@pytest.mark.check_health
def test_check_health_invalid_client_id(invalid_configuration, connector_id, connector_details, params_json):
    set_report_metadata(connector_details, "Health Check", "Verify with invalid Application (client) ID")
    result = run_invalid_config_test(invalid_configuration, connector_id, connector_details, param_name='client_id',
                                     param_type='text', config=params_json['config'])
    assert result.get('status') == "Disconnected"
    

@pytest.mark.check_health
def test_check_health_invalid_client_secret(invalid_configuration, connector_id, connector_details, params_json):
    set_report_metadata(connector_details, "Health Check", "Verify with invalid Application (Client) Secret")
    result = run_invalid_config_test(invalid_configuration, connector_id, connector_details, param_name='client_secret',
                                     param_type='password', config=params_json['config'])
    assert result.get('status') == "Disconnected"
    

@pytest.mark.list_key_vault
def test_list_key_vault_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "List Key Vaults", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='list_key_vault',
                                   action_params=params_json['list_key_vault']):
        assert result.get('status') == "Success"


@pytest.mark.list_key_vault
def test_validate_list_key_vault_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "List Key Vaults", "Validate Output Schema")
    run_output_schema_validation(cache, 'list_key_vault', info_json, params_json['list_key_vault'])
    

@pytest.mark.list_key_vault
def test_list_key_vault_invalid_size(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "List Key Vaults", "Verify with invalid Size")
    result = run_invalid_param_test(connector_details, operation_name='list_key_vault', param_name='size',
                                    param_type='integer', action_params=params_json['list_key_vault'])
    assert result.get('status') == "failed"
    

@pytest.mark.list_key_vault
def test_list_key_vault_invalid_skip_token(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "List Key Vaults", "Verify with invalid Skip Token")
    result = run_invalid_param_test(connector_details, operation_name='list_key_vault', param_name='skip_token',
                                    param_type='text', action_params=params_json['list_key_vault'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_key_vault
def test_get_key_vault_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Key Vault", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='get_key_vault',
                                   action_params=params_json['get_key_vault']):
        assert result.get('status') == "Success"


@pytest.mark.get_key_vault
def test_validate_get_key_vault_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get Key Vault", "Validate Output Schema")
    run_output_schema_validation(cache, 'get_key_vault', info_json, params_json['get_key_vault'])
    

@pytest.mark.get_key_vault
def test_get_key_vault_invalid_vault_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Key Vault", "Verify with invalid Vault Name")
    result = run_invalid_param_test(connector_details, operation_name='get_key_vault', param_name='vault_name',
                                    param_type='text', action_params=params_json['get_key_vault'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_key_vault
def test_get_key_vault_invalid_resource_group_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Key Vault", "Verify with invalid Resource Group Name")
    result = run_invalid_param_test(connector_details, operation_name='get_key_vault', param_name='resource_group_name',
                                    param_type='text', action_params=params_json['get_key_vault'])
    assert result.get('status') == "failed"
    

@pytest.mark.delete_key_vault
def test_delete_key_vault_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Delete Key Vault", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='delete_key_vault',
                                   action_params=params_json['delete_key_vault']):
        assert result.get('status') == "Success"


@pytest.mark.delete_key_vault
def test_validate_delete_key_vault_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Delete Key Vault", "Validate Output Schema")
    run_output_schema_validation(cache, 'delete_key_vault', info_json, params_json['delete_key_vault'])
    

@pytest.mark.delete_key_vault
def test_delete_key_vault_invalid_resource_group_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Delete Key Vault", "Verify with invalid Resource Group Name")
    result = run_invalid_param_test(connector_details, operation_name='delete_key_vault', param_name='resource_group_name',
                                    param_type='text', action_params=params_json['delete_key_vault'])
    assert result.get('status') == "failed"
    

@pytest.mark.update_vault_access_policy
def test_update_vault_access_policy_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Update Vault's Access Policies", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='update_vault_access_policy',
                                   action_params=params_json['update_vault_access_policy']):
        assert result.get('status') == "Success"


@pytest.mark.update_vault_access_policy
def test_validate_update_vault_access_policy_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Update Vault's Access Policies", "Validate Output Schema")
    run_output_schema_validation(cache, 'update_vault_access_policy', info_json, params_json['update_vault_access_policy'])
    

@pytest.mark.update_vault_access_policy
def test_update_vault_access_policy_invalid_vault_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Update Vault's Access Policies", "Verify with invalid Vault Name")
    result = run_invalid_param_test(connector_details, operation_name='update_vault_access_policy', param_name='vault_name',
                                    param_type='text', action_params=params_json['update_vault_access_policy'])
    assert result.get('status') == "failed"
    

@pytest.mark.update_vault_access_policy
def test_update_vault_access_policy_invalid_resource_group_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Update Vault's Access Policies", "Verify with invalid Resource Group Name")
    result = run_invalid_param_test(connector_details, operation_name='update_vault_access_policy', param_name='resource_group_name',
                                    param_type='text', action_params=params_json['update_vault_access_policy'])
    assert result.get('status') == "failed"
    

@pytest.mark.update_vault_access_policy
def test_update_vault_access_policy_invalid_accesspolicies(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Update Vault's Access Policies", "Verify with invalid Policies")
    result = run_invalid_param_test(connector_details, operation_name='update_vault_access_policy', param_name='accessPolicies',
                                    param_type='json', action_params=params_json['update_vault_access_policy'])
    assert result.get('status') == "failed"
    

@pytest.mark.list_keys
def test_list_keys_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get All Keys", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='list_keys',
                                   action_params=params_json['list_keys']):
        assert result.get('status') == "Success"


@pytest.mark.list_keys
def test_validate_list_keys_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get All Keys", "Validate Output Schema")
    run_output_schema_validation(cache, 'list_keys', info_json, params_json['list_keys'])
    

@pytest.mark.list_keys
def test_list_keys_invalid_vault_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get All Keys", "Verify with invalid Vault Name")
    result = run_invalid_param_test(connector_details, operation_name='list_keys', param_name='vault_name',
                                    param_type='text', action_params=params_json['list_keys'])
    assert result.get('status') == "failed"
    

@pytest.mark.list_keys
def test_list_keys_invalid_size(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get All Keys", "Verify with invalid Size")
    result = run_invalid_param_test(connector_details, operation_name='list_keys', param_name='size',
                                    param_type='integer', action_params=params_json['list_keys'])
    assert result.get('status') == "failed"
    

@pytest.mark.list_keys
def test_list_keys_invalid_skip_token(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get All Keys", "Verify with invalid Skip Token")
    result = run_invalid_param_test(connector_details, operation_name='list_keys', param_name='skip_token',
                                    param_type='text', action_params=params_json['list_keys'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_key
def test_get_key_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Key Details", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='get_key',
                                   action_params=params_json['get_key']):
        assert result.get('status') == "Success"


@pytest.mark.get_key
def test_validate_get_key_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get Key Details", "Validate Output Schema")
    run_output_schema_validation(cache, 'get_key', info_json, params_json['get_key'])
    

@pytest.mark.get_key
def test_get_key_invalid_key_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Key Details", "Verify with invalid Key Name")
    result = run_invalid_param_test(connector_details, operation_name='get_key', param_name='key_name',
                                    param_type='text', action_params=params_json['get_key'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_key
def test_get_key_invalid_vault_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Key Details", "Verify with invalid Vault Name")
    result = run_invalid_param_test(connector_details, operation_name='get_key', param_name='vault_name',
                                    param_type='text', action_params=params_json['get_key'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_key
def test_get_key_invalid_key_version(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Key Details", "Verify with invalid Key Version")
    result = run_invalid_param_test(connector_details, operation_name='get_key', param_name='key-version',
                                    param_type='text', action_params=params_json['get_key'])
    assert result.get('status') == "failed"
    

@pytest.mark.delete_key
def test_delete_key_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Delete Key", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='delete_key',
                                   action_params=params_json['delete_key']):
        assert result.get('status') == "Success"


@pytest.mark.delete_key
def test_validate_delete_key_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Delete Key", "Validate Output Schema")
    run_output_schema_validation(cache, 'delete_key', info_json, params_json['delete_key'])
    

@pytest.mark.delete_key
def test_delete_key_invalid_key_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Delete Key", "Verify with invalid Key Name")
    result = run_invalid_param_test(connector_details, operation_name='delete_key', param_name='key_name',
                                    param_type='text', action_params=params_json['delete_key'])
    assert result.get('status') == "failed"
    

@pytest.mark.delete_key
def test_delete_key_invalid_vault_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Delete Key", "Verify with invalid Vault Name")
    result = run_invalid_param_test(connector_details, operation_name='delete_key', param_name='vault_name',
                                    param_type='text', action_params=params_json['delete_key'])
    assert result.get('status') == "failed"
    

@pytest.mark.list_secret
def test_list_secret_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get All Secrets", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='list_secret',
                                   action_params=params_json['list_secret']):
        assert result.get('status') == "Success"


@pytest.mark.list_secret
def test_validate_list_secret_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get All Secrets", "Validate Output Schema")
    run_output_schema_validation(cache, 'list_secret', info_json, params_json['list_secret'])
    

@pytest.mark.list_secret
def test_list_secret_invalid_vault_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get All Secrets", "Verify with invalid Vault Name")
    result = run_invalid_param_test(connector_details, operation_name='list_secret', param_name='vault_name',
                                    param_type='text', action_params=params_json['list_secret'])
    assert result.get('status') == "failed"
    

@pytest.mark.list_secret
def test_list_secret_invalid_size(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get All Secrets", "Verify with invalid Size")
    result = run_invalid_param_test(connector_details, operation_name='list_secret', param_name='size',
                                    param_type='integer', action_params=params_json['list_secret'])
    assert result.get('status') == "failed"
    

@pytest.mark.list_secret
def test_list_secret_invalid_skip_token(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get All Secrets", "Verify with invalid Skip Token")
    result = run_invalid_param_test(connector_details, operation_name='list_secret', param_name='skip_token',
                                    param_type='text', action_params=params_json['list_secret'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_secret
def test_get_secret_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Secret Details", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='get_secret',
                                   action_params=params_json['get_secret']):
        assert result.get('status') == "Success"


@pytest.mark.get_secret
def test_validate_get_secret_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get Secret Details", "Validate Output Schema")
    run_output_schema_validation(cache, 'get_secret', info_json, params_json['get_secret'])
    

@pytest.mark.get_secret
def test_get_secret_invalid_secret_version(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Secret Details", "Verify with invalid Secret Version")
    result = run_invalid_param_test(connector_details, operation_name='get_secret', param_name='secret_version',
                                    param_type='text', action_params=params_json['get_secret'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_secret
def test_get_secret_invalid_vault_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Secret Details", "Verify with invalid Vault Name")
    result = run_invalid_param_test(connector_details, operation_name='get_secret', param_name='vault_name',
                                    param_type='text', action_params=params_json['get_secret'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_secret
def test_get_secret_invalid_secret_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Secret Details", "Verify with invalid Secret Name")
    result = run_invalid_param_test(connector_details, operation_name='get_secret', param_name='secret_name',
                                    param_type='text', action_params=params_json['get_secret'])
    assert result.get('status') == "failed"
    

@pytest.mark.delete_secret
def test_delete_secret_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Delete Secret", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='delete_secret',
                                   action_params=params_json['delete_secret']):
        assert result.get('status') == "Success"


@pytest.mark.delete_secret
def test_validate_delete_secret_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Delete Secret", "Validate Output Schema")
    run_output_schema_validation(cache, 'delete_secret', info_json, params_json['delete_secret'])
    

@pytest.mark.delete_secret
def test_delete_secret_invalid_vault_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Delete Secret", "Verify with invalid Vault Name")
    result = run_invalid_param_test(connector_details, operation_name='delete_secret', param_name='vault_name',
                                    param_type='text', action_params=params_json['delete_secret'])
    assert result.get('status') == "failed"
    

@pytest.mark.delete_secret
def test_delete_secret_invalid_secret_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Delete Secret", "Verify with invalid Secret Name")
    result = run_invalid_param_test(connector_details, operation_name='delete_secret', param_name='secret_name',
                                    param_type='text', action_params=params_json['delete_secret'])
    assert result.get('status') == "failed"
    

@pytest.mark.list_certificate
def test_list_certificate_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get All Certificates", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='list_certificate',
                                   action_params=params_json['list_certificate']):
        assert result.get('status') == "Success"


@pytest.mark.list_certificate
def test_validate_list_certificate_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get All Certificates", "Validate Output Schema")
    run_output_schema_validation(cache, 'list_certificate', info_json, params_json['list_certificate'])
    

@pytest.mark.list_certificate
def test_list_certificate_invalid_vault_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get All Certificates", "Verify with invalid Vault Name")
    result = run_invalid_param_test(connector_details, operation_name='list_certificate', param_name='vault_name',
                                    param_type='text', action_params=params_json['list_certificate'])
    assert result.get('status') == "failed"
    

@pytest.mark.list_certificate
def test_list_certificate_invalid_size(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get All Certificates", "Verify with invalid Size")
    result = run_invalid_param_test(connector_details, operation_name='list_certificate', param_name='size',
                                    param_type='integer', action_params=params_json['list_certificate'])
    assert result.get('status') == "failed"
    

@pytest.mark.list_certificate
def test_list_certificate_invalid_skip_token(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get All Certificates", "Verify with invalid Skip Token")
    result = run_invalid_param_test(connector_details, operation_name='list_certificate', param_name='skip_token',
                                    param_type='text', action_params=params_json['list_certificate'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_certificate
def test_get_certificate_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Certificate Details", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='get_certificate',
                                   action_params=params_json['get_certificate']):
        assert result.get('status') == "Success"


@pytest.mark.get_certificate
def test_validate_get_certificate_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get Certificate Details", "Validate Output Schema")
    run_output_schema_validation(cache, 'get_certificate', info_json, params_json['get_certificate'])
    

@pytest.mark.get_certificate
def test_get_certificate_invalid_certificate_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Certificate Details", "Verify with invalid Certificate Name")
    result = run_invalid_param_test(connector_details, operation_name='get_certificate', param_name='certificate_name',
                                    param_type='text', action_params=params_json['get_certificate'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_certificate
def test_get_certificate_invalid_vault_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Certificate Details", "Verify with invalid Vault Name")
    result = run_invalid_param_test(connector_details, operation_name='get_certificate', param_name='vault_name',
                                    param_type='text', action_params=params_json['get_certificate'])
    assert result.get('status') == "failed"
    

@pytest.mark.delete_certificate
def test_delete_certificate_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Delete Certificate", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='delete_certificate',
                                   action_params=params_json['delete_certificate']):
        assert result.get('status') == "Success"


@pytest.mark.delete_certificate
def test_validate_delete_certificate_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Delete Certificate", "Validate Output Schema")
    run_output_schema_validation(cache, 'delete_certificate', info_json, params_json['delete_certificate'])
    

@pytest.mark.delete_certificate
def test_delete_certificate_invalid_certificate_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Delete Certificate", "Verify with invalid Certificate Name")
    result = run_invalid_param_test(connector_details, operation_name='delete_certificate', param_name='certificate_name',
                                    param_type='text', action_params=params_json['delete_certificate'])
    assert result.get('status') == "failed"
    

@pytest.mark.delete_certificate
def test_delete_certificate_invalid_vault_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Delete Certificate", "Verify with invalid Vault Name")
    result = run_invalid_param_test(connector_details, operation_name='delete_certificate', param_name='vault_name',
                                    param_type='text', action_params=params_json['delete_certificate'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_certificate_policy
def test_get_certificate_policy_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Certificate Policy", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='get_certificate_policy',
                                   action_params=params_json['get_certificate_policy']):
        assert result.get('status') == "Success"


@pytest.mark.get_certificate_policy
def test_validate_get_certificate_policy_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get Certificate Policy", "Validate Output Schema")
    run_output_schema_validation(cache, 'get_certificate_policy', info_json, params_json['get_certificate_policy'])
    

@pytest.mark.get_certificate_policy
def test_get_certificate_policy_invalid_certificate_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Certificate Policy", "Verify with invalid Certificate Name")
    result = run_invalid_param_test(connector_details, operation_name='get_certificate_policy', param_name='certificate_name',
                                    param_type='text', action_params=params_json['get_certificate_policy'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_certificate_policy
def test_get_certificate_policy_invalid_vault_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Certificate Policy", "Verify with invalid Vault Name")
    result = run_invalid_param_test(connector_details, operation_name='get_certificate_policy', param_name='vault_name',
                                    param_type='text', action_params=params_json['get_certificate_policy'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_versions
def test_get_versions_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Versions", "Verify with valid Input Parameters")
    for result in run_success_test(cache, connector_details, operation_name='get_versions',
                                   action_params=params_json['get_versions']):
        assert result.get('status') == "Success"


@pytest.mark.get_versions
def test_validate_get_versions_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get Versions", "Validate Output Schema")
    run_output_schema_validation(cache, 'get_versions', info_json, params_json['get_versions'])
    

@pytest.mark.get_versions
def test_get_versions_invalid_vault_name(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Versions", "Verify with invalid Vault Name")
    result = run_invalid_param_test(connector_details, operation_name='get_versions', param_name='vault_name',
                                    param_type='text', action_params=params_json['get_versions'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_versions
def test_get_versions_invalid_size(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Versions", "Verify with invalid Size")
    result = run_invalid_param_test(connector_details, operation_name='get_versions', param_name='size',
                                    param_type='integer', action_params=params_json['get_versions'])
    assert result.get('status') == "failed"
    

@pytest.mark.get_versions
def test_get_versions_invalid_skip_token(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Versions", "Verify with invalid Skip Token")
    result = run_invalid_param_test(connector_details, operation_name='get_versions', param_name='skip_token',
                                    param_type='text', action_params=params_json['get_versions'])
    assert result.get('status') == "failed"
    
