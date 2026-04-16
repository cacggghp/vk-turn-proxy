package main

import (
	"fmt"
	"math/rand"
	"strings"
)

var maleFirstNames = []string{
	"Александр",
	"Алексей",
	"Андрей",
	"Антон",
	"Арсений",
	"Артур",
	"Артём",
	"Богдан",
	"Валерий",
	"Василий",
	"Виктор",
	"Владислав",
	"Глеб",
	"Григорий",
	"Даниил",
	"Денис",
	"Дмитрий",
	"Евгений",
	"Егор",
	"Иван",
	"Игорь",
	"Илья",
	"Кирилл",
	"Леонид",
	"Максим",
	"Марк",
	"Матвей",
	"Михаил",
	"Никита",
	"Николай",
	"Олег",
	"Павел",
	"Пётр",
	"Роман",
	"Руслан",
	"Сергей",
	"Станислав",
	"Тимофей",
	"Фёдор",
}

var femaleFirstNames = []string{
	"Алина",
	"Алёна",
	"Анастасия",
	"Ангелина",
	"Анна",
	"Вера",
	"Вероника",
	"Виктория",
	"Дарья",
	"Ева",
	"Екатерина",
	"Елена",
	"Елизавета",
	"Ирина",
	"Кира",
	"Кристина",
	"Ксения",
	"Любовь",
	"Маргарита",
	"Марина",
	"Мария",
	"Милана",
	"Надежда",
	"Наталья",
	"Ольга",
	"Полина",
	"Светлана",
	"София",
	"Татьяна",
	"Юлия",
	"Яна",
}

var lastNames = []string{
	"Алексеев",
	"Андреев",
	"Антонов",
	"Баранов",
	"Белов",
	"Белый",
	"Бельский",
	"Беляев",
	"Борисов",
	"Васильев",
	"Великий",
	"Волков",
	"Воробьёв",
	"Григорьев",
	"Давыдов",
	"Егоров",
	"Жуков",
	"Зайцев",
	"Захаров",
	"Иванов",
	"Калинин",
	"Ковалёв",
	"Козлов",
	"Комаров",
	"Крамской",
	"Кузнецов",
	"Кузьмин",
	"Лебедев",
	"Макаров",
	"Медведев",
	"Михайлов",
	"Морозов",
	"Никитин",
	"Николаев",
	"Новиков",
	"Орлов",
	"Островский",
	"Павлов",
	"Петров",
	"Покровский",
	"Попов",
	"Раевский",
	"Романов",
	"Семёнов",
	"Сергеев",
	"Смирнов",
	"Соколов",
	"Соловьёв",
	"Степанов",
	"Тарасов",
	"Титов",
	"Толстой",
	"Трубецкой",
	"Филиппов",
	"Фролов",
	"Фёдоров",
	"Чайковский",
	"Черный",
	"Яковлев",
}

// convertToFemaleSurname handles Russian suffix rules
func convertToFemaleSurname(surname string) string {
	// Handle adjective-style surnames:
	if strings.HasSuffix(surname, "ий") || strings.HasSuffix(surname, "ый") || strings.HasSuffix(surname, "ой") {
		return surname[:len(surname)-4] + "ая"
	}

	// Handle standard possessive surnames:
	if strings.HasSuffix(surname, "ов") || strings.HasSuffix(surname, "ев") ||
		strings.HasSuffix(surname, "ин") || strings.HasSuffix(surname, "ын") ||
		strings.HasSuffix(surname, "ёв") {
		return surname + "а"
	}

	// Foreign or unchangeable
	return surname
}

func generateName() string {
	// Decide gender first
	isFemale := rand.Intn(2) == 0

	var fn string
	if isFemale {
		fn = femaleFirstNames[rand.Intn(len(femaleFirstNames))]
	} else {
		fn = maleFirstNames[rand.Intn(len(maleFirstNames))]
	}

	// 70% chance to have a last name
	if rand.Float32() < 0.3 {
		return fn
	}

	ln := lastNames[rand.Intn(len(lastNames))]
	if isFemale {
		ln = convertToFemaleSurname(ln)
	}

	return fmt.Sprintf("%s %s", fn, ln)
}
