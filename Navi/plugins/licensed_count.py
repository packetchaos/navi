from .api_wrapper import request_data


def get_licensed():
    data = request_data('GET', '/workbenches/asset-stats?date_range=90&filter.0.filter=is_licensed&filter.0.quality=eq&filter.0.value=true')
    number_of_assets = data['scanned']
    return number_of_assets
