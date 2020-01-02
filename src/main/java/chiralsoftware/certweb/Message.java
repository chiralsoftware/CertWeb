package chiralsoftware.certweb;

import java.util.logging.Level;


/**
 * Show messages to the user
 */
final class Message {
    
    private final Level level;
    private final String string;

    Message(Level level, String string) {
        this.level = level;
        this.string = string;
    }

    public Level getLevel() {
        return level;
    }

    public String getString() {
        return string;
    }

    @Override
    public String toString() {
        return "Message{" + "level=" + level + ", string=" + string + '}';
    }
    
}
