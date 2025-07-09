## KanaQuest
A web and mobile application for learning Hiragana, Katakana, and potentially Kanji, built with Angular 20, Spring Boot, PrimeNG, Tailwind CSS, and MariaDB.

## Structure
angular/: Angular 20 frontend with PrimeNG and Tailwind.
spring/: Spring Boot backend with Spring Authorization Server and MariaDB.
mobile/: Placeholder for future Ionic mobile app.
shared/: Shared TypeScript interfaces (e.g., Progress, User).

## Setup

### Backend:
cd spring
mvn spring-boot:run

### Frontend:
cd angular
npm install
ng serve

### Database: Run MariaDB locally

### Authentication
   Uses OAuth2 with PKCE via Spring Authorization Server.
