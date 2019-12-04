$(function(){

	$('#connect-form').submit(function(ev){
		$.post('/start', $('#connect-form').serialize(), function(data){
			$('.before-submit').hide();
			$('#submit-message').removeClass('hidden');
		});
		ev.preventDefault();
	});
});
