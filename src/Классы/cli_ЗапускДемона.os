&КомандаПриложения(Имя = "start-daemon", Описание = "Запуск службы Windows под названием OproxyDaemon, созданной с помощью команды create-daemon")
Процедура ПриСозданииОбъекта()	
КонецПроцедуры

&ВыполнениеКоманды
Процедура ЗапуститьДемона() Экспорт
	РаботаСДемоном.Запустить();
КонецПроцедуры