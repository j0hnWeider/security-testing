import { allure } from 'allure-playwright';

export class AllureHelper {
  static addSeverity(severity: 'blocker' | 'critical' | 'normal' | 'minor' | 'trivial'): void {
    allure.severity(severity);
  }

  static addTags(...tags: string[]): void {
    tags.forEach(tag => allure.tag(tag));
  }

  static addDescription(text: string): void {
    allure.description(text);
  }

  static addLink(name: string, url: string, type?: string): void {
    allure.link(url, name, type);
  }

  static addParameter(name: string, value: string): void {
    allure.addParameter(name, value);
  }

  static addTestCaseId(id: string): void {
    allure.addParameter('testCaseId', id);
  }

  static addAttachment(name: string, content: string | Buffer, type: string): void {
    allure.attachment(name, content, type);
  }

  static async addStep<T>(name: string, fn: () => Promise<T>): Promise<T> {
    return allure.step(name, fn);
  }

  static addFeature(feature: string): void {
    allure.feature(feature);
  }

  static addStory(story: string): void {
    allure.story(story);
  }

  static addEnvironment(key: string, value: string): void {
    allure.addEnvironment(key, value);
  }
}
