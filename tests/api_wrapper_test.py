from navi.plugins.api_wrapper import (
    grab_headers,
    request_data,
    request_delete
)


# Test example
def test_grab_headers():
    result = grab_headers()
    assert type(result) is dict
    assert result['user-agent'] == 'navi-5.0.0'
