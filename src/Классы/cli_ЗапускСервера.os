&Пластилин
Перем ЗапускательСервера;

&Опция(Имя = "proxy-port", Описание = "Порт, который будет слушать прокси-сервер. К этому порту будет подключаться конфигуратор. Порт должен быть открыт в фаерволе, если вы подключаетесь к хранилищу по сети")
&ТЧисло
&Обязательный
Перем ПортПрокси Экспорт;

&Опция(Имя = "storage-server", Описание = "Адрес вашего сервера хранилища без tcp:// и прочих слешей и портов (порт - следующий параметр). Если сервер располагается на той же машине, на которой запущен прокси-сервер, укажите localhost или 127.0.0.1")
&ТСтрока
&Обязательный
Перем АдресСервера Экспорт;

&Опция(Имя = "storage-port", Описание = "Порт вашего сервера хранилища, указанного в предыдущем параметре. Например 1542")
&ТЧисло
&Обязательный
Перем ПортСервера Экспорт;


&КомандаПриложения(Имя = "s start", Описание = "Запуск сервера")
Процедура ПриСозданииОбъекта()	
КонецПроцедуры

&ВыполнениеКоманды
Процедура Запустить() Экспорт
	Сообщить("Запуск TCP прокси-сервера хранилища 1С");
	Сообщить("Для остановки прокси-сервера нажмите Ctrl+C");
	ЗапускательСервера.ПортПрокси = ПортПрокси;
	ЗапускательСервера.АдресСервера = АдресСервера;
	ЗапускательСервера.ПортСервера = ПортСервера;
	ЗапускательСервера.Запустить();
КонецПроцедуры