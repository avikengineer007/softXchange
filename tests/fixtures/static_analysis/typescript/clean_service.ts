interface User {
    id: string;
    username: string;
    email: string;
}

export class UserService {
    private users: Map<string, User> = new Map();

    public getUser(id: string): User | undefined {
        return this.users.get(id);
    }

    public addUser(user: User): void {
        this.users.set(user.id, user);
    }
}
