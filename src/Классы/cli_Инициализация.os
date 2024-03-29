&Опция(Имя = "f force", Описание = "(необязательный) перезаписывает существующий файл ПроверкиПроксиСервера")
&ТБулево
Перем Насильно Экспорт;

&Опция(Имя = "fp file-path", Описание = "(необязательный) полный путь к файлу проверок, если не хотите создавать в текущем каталоге")
&ТСтрока
Перем ПутьКФайлуПользователя Экспорт;

&КомандаПриложения(Имя = "i init", Описание = "Инициализация каталога. По умолчанию будет создан файл ""ПроверкиПроксиСервера.os"" в текущием каталоге (если файл отсутствует). Если файл существует, будет ошибка.")
Процедура ПриСозданииОбъекта()	
КонецПроцедуры

&ВыполнениеКоманды
Процедура Инициализировать() Экспорт
	ИмяМодуля = "ПроверкиПроксиСервера";
	ИмяФайла = СтрШаблон("%1.os", ИмяМодуля);
	ПутьКФайлу = "";
	Если ЗначениеЗаполнено(ПутьКФайлуПользователя) Тогда
		ПутьКФайлу = ПутьКФайлуПользователя;
	Иначе
		ПутьКФайлу = ОбъединитьПути(ТекущийКаталог(), ИмяФайла);
	КонецЕсли;
	Файл = Новый Файл(ПутьКФайлу);
	Если Насильно <> Истина И Файл.Существует() Тогда
		ТекстОшибки = СтрШаблон("Невозможно добавить %1, так как он уже существует.
		|Чтобы не потерять ваши существующие правила, переместите его в другое место.
		|Сделайте бэкап, переименуйте, что угодно!
		|Для перезаписи существующего файла можно использовать параметр --force", ПутьКФайлу);
		Сообщить(ТекстОшибки);
		Возврат;
	КонецЕсли;
	ЧтоЗаменить = ОбъединитьПути("src", "Классы");
	НаЧтоЗаменить = ОбъединитьПути("features", СтрШаблон("%1_Пример.os", ИмяМодуля));
	Откуда = СтрЗаменить(ТекущийСценарий().Каталог, ЧтоЗаменить, НаЧтоЗаменить);
	Попытка
		КопироватьФайл(Откуда, ПутьКФайлу);
		Сообщить(СтрШаблон("Инициализация проведена! Открывайте файл %1 и вносите свои правила и веб-хуки!", ПутьКФайлу));
	Исключение
		Сообщить(СтрШаблон("Не удалось скопировать файл из %1 в %2 по причине: %3", Откуда, ПутьКФайлу, ОписаниеОшибки()));
	КонецПопытки;
КонецПроцедуры