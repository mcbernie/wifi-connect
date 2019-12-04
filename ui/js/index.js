$(function(){
	var networks = undefined;

	function showSettingsFields() {
		var field_to_show = $(this).find(':selected').attr('value');
		$('#ethernet').hide();
		$('#ethernet-dhcp').hide();
		$('#wlan').hide();

		$('#' + field_to_show).show();
	}

	$('#ethernet').hide();
	$('#ethernet-dhcpp').hide();
	$('#wlan').hide();

	$('#eth_ipaddress').ipaddress();
	$('#eth_subnet').ipaddress();
	$('#eth_gateway').ipaddress();
	$('#eth_dns').ipaddress();

	function showHideEnterpriseSettings() {
		var security = $(this).find(':selected').attr('data-security');
		if(security === 'enterprise') {
			$('#identity-group').show();
		} else {
			$('#identity-group').hide();
		}
	}

	$('#ssid-select').change(showHideEnterpriseSettings);
	$('#network-select').change(showSettingsFields);

	$.get("/networks", function(data){
		
			config = JSON.parse(data);

			if ( config.ssids.length > 0) {

				$('#network-select').append(
					$('<option>')
							.text("WLAN")
							.attr('value', "wlan")
				);
				$('#wlan').show();
			} {
				$('#wlan').hide();
			}

			if (config.ethernet) {
				$('#network-select').append(
					$('<option>')
							.text(" Kabelgebundenes Netzwerk - DHCP")
							.attr('value', "ethernet-dhcp")
				);

				$('#network-select').append(
					$('<option>')
							.text(" Kabelgebundenes Netzwerk - Manuell")
							.attr('value', "ethernet")
				);

				if (config.ethernet.Static && config.ethernet.Static .length >= 0) {
					$('#eth_ipaddress').val(config.ethernet.Static[0]);
					$('#eth_subnet').val(config.ethernet.Static[1]);
					$('#eth_gateway').val(config.ethernet.Static[2]);
					$('#eth_dns').val(config.ethernet.Static[3]);
				}

				if (config.ethernet.Dhcp && config.ethernet.Dhcp.length >= 0) {
					$('#eth_ipaddress').val(config.ethernet.Static[0]);
					$('#eth_subnet').val(config.ethernet.Static[1]);
					$('#eth_gateway').val(config.ethernet.Static[2]);
					$('#eth_dns').val(config.ethernet.Static[3]);
				}
			}

			jQuery.proxy(showSettingsFields, $('#network-select'))();

			if(config.ssids.length === 0){
				$('.before-submit').hide();
				$('#no-networks-message').removeClass('hidden');
			} else {
				$.each(config.ssids, function(i, val){
					$('#ssid-select').append(
						$('<option>')
							.text(val.ssid)
							.attr('value', val.ssid)
							.attr('data-security', val.security)
					);
				});

				jQuery.proxy(showHideEnterpriseSettings, $('#ssid-select'))();
			}
			
	});

	$('#connect-form').submit(function(ev){
		$.post('/connect', $('#connect-form').serialize(), function(data){
			$('.before-submit').hide();
			$('#submit-message').removeClass('hidden');
		});
		ev.preventDefault();
	});
});
