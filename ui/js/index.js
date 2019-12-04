$(function(){
	var networks = undefined;

	function showHideEnterpriseSettings() {
		var field_to_show = $(this).find(':selected').attr('value');
		$('#ethernet').hide();
		$('#ethernet-dhcp').hide();
		$('#wlan').hide();

		$('#' + field_to_show).show();

		

	}

	$('#ethernet').hide();
	$('#ethernet-dhcpp').hide();
	$('#wlan').hide();

	function showSettingsFields() {
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

			/*$.each(config, function(i, val){
				$('#network-select').append(
					$('<option>')
						.text(val.name)
						.attr('value', val.id)
						.attr('data-config', val.config)
				);
			});*/

			$('#network-select').append(
				$('<option>')
						.text("WLAN")
						.attr('value', "wlan")
			);

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
